/*	$OpenBSD$	*/

/*
 * Copyright (c) 2017, 2021 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "gelatod.h"

#define	PAIR_DEVICE	2
#define	RTABLE		0
#define	PF_ANCHOR	"clat"

enum gelatod_process {
	PROC_MAIN,
	PROC_FRONTEND
};

__dead void	usage(void);
__dead void	main_shutdown(void);

void		main_sig_handler(int, short, void *);

static pid_t	start_child(enum gelatod_process, char *, int, int, int);

void		main_dispatch_frontend(int, short, void *);

int		main_imsg_compose_frontend(int, int, void *, uint16_t);
void		solicit_dns_proposals(void);
void		configure_clat(struct clat_imsg *);

static struct imsgev	*iev_frontend;
pid_t			 frontend_pid, pfctl_pid;
int			 routesock, ioctl_sock, rtm_seq = 0;

void
main_sig_handler(int sig, short event, void *arg)
{
	pid_t	 pid = 0;
	int	 status;

	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
		break;
	case SIGCHLD:
		if (pfctl_pid != 0) {
			pid = waitpid(pfctl_pid, &status, WNOHANG);
		}
		if (pid <= 0 || pid != pfctl_pid)
			main_shutdown();
		pfctl_pid = 0;
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event		 ev_sigint, ev_sigterm, ev_sigchld;
	int			 ch;
	int			 debug = 0, frontend_flag = 0;
	int			 verbose = 0;
	char			*saved_argv0;
	int			 pipe_main2frontend[2];
	int			 lockfd;

	log_init(1, LOG_DAEMON);	/* Log to stderr until daemonized. */
	log_setverbose(1);

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = "gelatod";

	while ((ch = getopt(argc, argv, "dFv")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'F':
			frontend_flag = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	if (frontend_flag)
		frontend(debug, verbose);

	/* Check for root privileges. */
	if (geteuid())
		errx(1, "need root privileges");

	lockfd = open(_PATH_LOCKFILE, O_CREAT|O_RDWR|O_EXLOCK|O_NONBLOCK, 0600);
	if (lockfd == -1)
		errx(1, "already running");

	/* Check for assigned daemon user */
	if (getpwnam(GELATOD_USER) == NULL)
		errx(1, "unknown user %s", GELATOD_USER);

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (!debug)
		daemon(0, 0);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2frontend) == -1)
		fatal("main2frontend socketpair");

	/* Start children. */
	frontend_pid = start_child(PROC_FRONTEND, saved_argv0,
	    pipe_main2frontend[1], debug, verbose);

	log_procinit("main");

	if ((routesock = socket(AF_ROUTE, SOCK_RAW | SOCK_CLOEXEC |
	    SOCK_NONBLOCK, 0)) == -1)
		fatal("route socket");
	shutdown(SHUT_RD, routesock);

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipes to children. */

	if ((iev_frontend = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_frontend->ibuf, pipe_main2frontend[0]);
	iev_frontend->handler = main_dispatch_frontend;

	/* Setup event handlers for pipes to frontend. */
	iev_frontend->events = EV_READ;
	event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
	    iev_frontend->events, iev_frontend->handler, iev_frontend);
	event_add(&iev_frontend->ev, NULL);

	if ((ioctl_sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		fatal("socket");


	if (pledge("stdio proc exec", NULL) == -1)
		fatal("pledge");

	main_imsg_compose_frontend(IMSG_STARTUP, -1, NULL, 0);

	event_dispatch();

	main_shutdown();
	return (0);
}

__dead void
main_shutdown(void)
{
	pid_t	 pid;
	int	 status;

	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("frontend terminated; signal %d",
			    WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_frontend);

	log_info("terminating");
	exit(0);
}

static pid_t
start_child(enum gelatod_process p, char *argv0, int fd, int debug, int verbose)
{
	char	*argv[7];
	int	 argc = 0;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (fd != 3) {
		if (dup2(fd, 3) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_FRONTEND:
		argv[argc++] = "-F";
		break;
	}
	if (debug)
		argv[argc++] = "-d";
	if (verbose)
		argv[argc++] = "-v";
	if (verbose > 1)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

void
main_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct clat_imsg	 clat_imsg;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_STARTUP_DONE:
			solicit_dns_proposals();
			break;
		case IMSG_CLAT:
			if (IMSG_DATA_SIZE(imsg) != sizeof(clat_imsg)) {
				fatalx("%s: IMSG_CLAT wrong length: "
				    "%lu", __func__, IMSG_DATA_SIZE(imsg));
			}
			memcpy(&clat_imsg, imsg.data, sizeof(clat_imsg));
			configure_clat(&clat_imsg);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}


int
main_imsg_compose_frontend(int type, int fd, void *data, uint16_t datalen)
{
	if (iev_frontend)
		return (imsg_compose_event(iev_frontend, type, 0, 0, fd, data,
		    datalen));
	else
		return (-1);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen)) != -1)
		imsg_event_add(iev);

	return (ret);
}

const char*
sin6_to_str(struct sockaddr_in6 *sin6)
{
	static char hbuf[NI_MAXHOST];
	int error;

	error = getnameinfo((struct sockaddr *)sin6, sin6->sin6_len, hbuf,
	    sizeof(hbuf), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
	if (error) {
		log_warnx("%s", gai_strerror(error));
		strlcpy(hbuf, "unknown", sizeof(hbuf));
	}
	return hbuf;
}

void
solicit_dns_proposals(void)
{
	struct rt_msghdr		 rtm;
	struct iovec			 iov[1];
	int				 iovcnt = 0;

	memset(&rtm, 0, sizeof(rtm));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_PROPOSAL;
	rtm.rtm_msglen = sizeof(rtm);
	rtm.rtm_tableid = 0;
	rtm.rtm_index = 0;
	rtm.rtm_seq = arc4random();
	rtm.rtm_priority = RTP_PROPOSAL_SOLICIT;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt++].iov_len = sizeof(rtm);

	if (writev(routesock, iov, iovcnt) == -1)
		log_warn("failed to send solicitation");
}

void
configure_clat(struct clat_imsg *clat_imsg)
{
	int	 len;
	int	 s_in[2], s_out[2], s_err[2];
	char	*argv[6];
	char	 pf_buf[sizeof("pass in log quick on pair255 inet af-to inet6 "
		    "from 0000:0000:0000:0000:0000:0000:0000:0000 to "
		    "0000:0000:0000:0000:0000:0000:0000:0000/128 "
		    "rtable 255\n")];
	char	 buf_from[INET6_ADDRSTRLEN];
	char	 buf_to[INET6_ADDRSTRLEN];

	if (clat_imsg->enable) {
		inet_ntop(AF_INET6, &clat_imsg->from, buf_from,
		    sizeof(buf_from));
		inet_ntop(AF_INET6, &clat_imsg->to, buf_to, sizeof(buf_to));
		len =snprintf(pf_buf, sizeof(pf_buf), "pass in log quick on "
		    "pair%d inet af-to inet6 from %s to %s/%d rtable %d\n",
		    PAIR_DEVICE, buf_from, buf_to,  clat_imsg->prefixlen,
		    RTABLE);
		if (len == -1 || (size_t)len >= sizeof(pf_buf))
			fatalx("couldn't form PF rule");
		log_info("Enabling CLAT %s -> %s/%d", buf_from, buf_to,
		    clat_imsg->prefixlen);
	} else {
		pf_buf[0] = '\n';
		pf_buf[1] = '\0';
		len = 1;
		log_info("Disabling CLAT");
	}

	log_debug("%s: %s", __func__, pf_buf);


	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, s_in) == -1)
		fatal("socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, s_out) == -1)
		fatal("socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, s_err) == -1)
		fatal("socketpair");

	switch (pfctl_pid = fork()) {
	case -1:
		fatal("fork");
		break;
	case 0:
		/* Child process */
		if (pledge("stdio exec", NULL) == -1)
			fatal("pledge");

		close(s_in[0]);
		close(s_out[0]);
		close(s_err[0]);

		if (dup2(s_in[1], STDIN_FILENO) == -1)
			_exit(1);
		if (dup2(s_out[1], STDOUT_FILENO) == -1)
			_exit(1);
		if (dup2(s_err[1], STDERR_FILENO) == -1)
			_exit(1);

		close(s_in[1]);
		close(s_out[1]);
		close(s_err[1]);

		signal(SIGPIPE, SIG_DFL);

		argv[0] = "/sbin/pfctl";
		argv[1] = "-a";
		argv[2] = PF_ANCHOR;
		argv[3] = "-f";
		argv[4] = "-";
		argv[5] = NULL;
		execv("/sbin/pfctl", argv);
		log_warn("execv");
		_exit(1);
	}
	/* Parent process*/
	close(s_in[1]);
	close(s_out[1]);
	close(s_err[1]);

	close(s_out[0]);
	close(s_err[0]);

	write(s_in[0], pf_buf, len);
	close(s_in[0]);
}
