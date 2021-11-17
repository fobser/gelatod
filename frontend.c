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
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <asr.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "gelatod.h"

#define	ROUTE_SOCKET_BUF_SIZE	16384

#define	WKA1_FOUND		1
#define	WKA2_FOUND		2

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

struct dns_ctx {
	void		*asr_ctx;
	uint32_t	 if_index;
};

struct iface		{
	LIST_ENTRY(iface)	 entries;
	struct ether_addr	 hw_address;
	struct sockaddr_rtdns	 rtdns;
	struct in6_addr		 in6;
	struct in6_addr		 dns64_prefix;
	int			 dns64_prefixlen;
	int			 dns64_enabled;
	uint32_t		 if_index;
	int			 rdomain;
	int			 link_state;
	int			 dns_done;
};

struct dns64_prefix {
	struct in6_addr	 in6;
	int		 prefixlen;
	int		 flags;
};

__dead void	 frontend_shutdown(void);
void		 frontend_sig_handler(int, short, void *);
void		 frontend_dispatch_main(int, short, void *);
int		 frontend_imsg_compose_main(int, pid_t, void *, uint16_t);
void		 update_iface(uint32_t, char*);
void		 frontend_startup(void);
void		 route_receive(int, short, void *);
void		 handle_route_message(struct rt_msghdr *, struct sockaddr **);
void		 get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
void		 handle_ipv6_resolvers(struct sockaddr_rtdns *, uint32_t);
void		 check_dns64_done(struct asr_result *, void *);
int		 dns64_preflen(const struct in6_addr *, const uint8_t *);
void		 add_dns64_prefix(const struct in6_addr *, int,
		     struct dns64_prefix *, int, int);
void		 update_clat(uint32_t);
int		 get_flags(char *);
int		 get_xflags(char *);
int		 get_ifrdomain(char *);
struct iface	*get_iface_by_id(uint32_t);
void		 remove_iface(uint32_t);
const char	*flags_to_str(int);

LIST_HEAD(, iface)		 interfaces;
static struct imsgev		*iev_main;
struct event			 ev_route;
int				 ioctlsock;

void
frontend_sig_handler(int sig, short event, void *bula)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		frontend_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
frontend(int debug, int verbose)
{
	struct event	 ev_sigint, ev_sigterm;
	struct passwd	*pw;
	int		 routesock, rtfilter, rtable_any = RTABLE_ANY;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((routesock = socket(AF_ROUTE, SOCK_RAW | SOCK_CLOEXEC,
	    AF_INET6)) == -1)
		fatal("route socket");

	rtfilter = ROUTE_FILTER(RTM_IFINFO) | ROUTE_FILTER(RTM_NEWADDR) |
	    ROUTE_FILTER(RTM_DELADDR) | ROUTE_FILTER(RTM_CHGADDRATTR) |
	    ROUTE_FILTER(RTM_PROPOSAL) | ROUTE_FILTER(RTM_IFANNOUNCE);
	if (setsockopt(routesock, AF_ROUTE, ROUTE_MSGFILTER,
	    &rtfilter, sizeof(rtfilter)) == -1)
		fatal("setsockopt(ROUTE_MSGFILTER)");
	if (setsockopt(routesock, AF_ROUTE, ROUTE_TABLEFILTER,
	    &rtable_any, sizeof(rtable_any)) == -1)
		fatal("setsockopt(ROUTE_TABLEFILTER)");

	if ((pw = getpwnam(GELATOD_USER)) == NULL)
		fatal("getpwnam");

	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (unveil("/", "") == -1)
		fatal("unveil /");
	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	setproctitle("%s", "frontend");
	log_procinit("frontend");

	if ((ioctlsock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		fatal("socket");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio dns route", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, frontend_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, frontend_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the parent process. */
	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = frontend_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	event_set(&ev_route, routesock, EV_READ | EV_PERSIST,
	    route_receive, NULL);
	event_add(&ev_route, NULL);

	LIST_INIT(&interfaces);

	event_dispatch();

	frontend_shutdown();
}

__dead void
frontend_shutdown(void)
{
	/* Close pipes. */
	msgbuf_write(&iev_main->ibuf.w);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	free(iev_main);

	log_info("frontend exiting");
	exit(0);
}

int
frontend_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data,
	    datalen));
}

void
frontend_dispatch_main(int fd, short event, void *bula)
{
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	ssize_t			 n;
	int			 shut = 0;

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
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_STARTUP:
			frontend_startup();
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
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
get_flags(char *if_name)
{
	struct ifreq		 ifr;

	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(ioctlsock, SIOCGIFFLAGS, (caddr_t)&ifr) == -1) {
		log_warn("SIOCGIFFLAGS");
		return -1;
	}
	return ifr.ifr_flags;
}

int
get_xflags(char *if_name)
{
	struct ifreq		 ifr;

	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(ioctlsock, SIOCGIFXFLAGS, (caddr_t)&ifr) == -1) {
		log_warn("SIOCGIFXFLAGS");
		return -1;
	}
	return ifr.ifr_flags;
}

int
get_ifrdomain(char *if_name)
{
	struct ifreq		 ifr;

	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(ioctlsock, SIOCGIFRDOMAIN, (caddr_t)&ifr) == -1) {
		log_warn("SIOCGIFRDOMAIN");
		return -1;
	}
	return ifr.ifr_rdomainid;
}

void
update_iface(uint32_t if_index, char* if_name)
{
	struct iface		*iface;
	struct ifaddrs		*ifap, *ifa;
	struct sockaddr_dl	*sdl;
	struct sockaddr_in6	*sin6, selected_sin6;
	struct in6_ifreq	 ifr6;
	struct in6_addrlifetime *lifetime;
	time_t			 t, vltime, pltime;
	int			 flags, xflags, ifrdomain, temporary;
	int			 selected_temporary, selected_deprecated;

	if ((flags = get_flags(if_name)) == -1 || (xflags =
	    get_xflags(if_name)) == -1)
		return;

	if (!(xflags & (IFXF_AUTOCONF6 | IFXF_AUTOCONF6TEMP)))
		return;

	if((ifrdomain = get_ifrdomain(if_name)) == -1)
		return;

	iface = get_iface_by_id(if_index);

	if (iface != NULL) {
		if (iface->rdomain != ifrdomain) {
			iface->rdomain = ifrdomain;
		}
	} else {
		if ((iface = calloc(1, sizeof(*iface))) == NULL)
			fatal("calloc");
		iface->if_index = if_index;
		iface->rdomain = ifrdomain;

		LIST_INSERT_HEAD(&interfaces, iface, entries);
	}

	if (getifaddrs(&ifap) != 0)
		fatal("getifaddrs");

	memset(&selected_sin6, 0, sizeof(selected_sin6));
	selected_temporary = 0;
	selected_deprecated = 1;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(if_name, ifa->ifa_name) != 0)
			continue;
		if (ifa->ifa_addr == NULL)
			continue;

		switch(ifa->ifa_addr->sa_family) {
		case AF_LINK:
			iface->link_state =
			    ((struct if_data *)ifa->ifa_data)->ifi_link_state;
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_type != IFT_ETHER ||
			    sdl->sdl_alen != ETHER_ADDR_LEN)
				continue;
			memcpy(iface->hw_address.ether_addr_octet,
			    LLADDR(sdl), ETHER_ADDR_LEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				break;

			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, if_name, sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, sin6, sizeof(ifr6.ifr_addr));

			if (ioctl(ioctlsock, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6)
			    == -1) {
				log_warn("SIOCGIFAFLAG_IN6");
				break;
			}

			if (!(ifr6.ifr_ifru.ifru_flags6 & (IN6_IFF_AUTOCONF |
			    IN6_IFF_TEMPORARY)))
				break;
			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DUPLICATED)
				break;
			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TENTATIVE)
				break;

			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TEMPORARY)
				temporary =  1;
			else
				temporary = 0;

			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, if_name, sizeof(ifr6.ifr_name));
			memcpy(&ifr6.ifr_addr, sin6, sizeof(ifr6.ifr_addr));
			lifetime = &ifr6.ifr_ifru.ifru_lifetime;

			if (ioctl(ioctlsock, SIOCGIFALIFETIME_IN6,
			    (caddr_t)&ifr6) == -1) {
				log_warn("SIOCGIFALIFETIME_IN6");
				break;
			}
			vltime = ND6_INFINITE_LIFETIME;
			pltime = ND6_INFINITE_LIFETIME;

			t = time(NULL);

			if (lifetime->ia6t_preferred)
				pltime = lifetime->ia6t_preferred < t ? 0
				    : lifetime->ia6t_preferred - t;

			if (lifetime->ia6t_expire)
				vltime = lifetime->ia6t_expire < t ? 0 :
				    lifetime->ia6t_expire - t;

			if (IN6_IS_ADDR_UNSPECIFIED(&selected_sin6.sin6_addr)) {
				selected_deprecated = pltime == 0;
				selected_temporary = temporary;
				memcpy(&selected_sin6, sin6,
				    sizeof(selected_sin6));
			} else if (selected_deprecated && pltime > 0) {
				selected_deprecated = 0;
				selected_temporary = temporary;
				memcpy(&selected_sin6, sin6,
				    sizeof(selected_sin6));
			} else if (!selected_temporary && temporary &&
			    pltime > 0) {
				selected_deprecated = 0;
				selected_temporary = temporary;
				memcpy(&selected_sin6, sin6,
				    sizeof(selected_sin6));

			}
			log_debug("%s: %s, temporary: %d, pltime: %lld, "
			    "vltime: %lld", __func__, sin6_to_str(sin6),
			    temporary, pltime, vltime);
			break;
		default:
			break;
		}
	}

	log_debug("selected: %s", sin6_to_str(&selected_sin6));
	if (memcmp(&iface->in6, &selected_sin6.sin6_addr,
	    sizeof(struct in6_addr)) != 0) {
		memcpy(&iface->in6, &selected_sin6.sin6_addr,
		    sizeof(struct in6_addr));
		update_clat(if_index);
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&iface->in6) && !iface->dns_done)
		handle_ipv6_resolvers(&iface->rtdns, iface->if_index);
	freeifaddrs(ifap);
}

const char*
flags_to_str(int flags)
{
	static char	buf[sizeof(" anycast tentative duplicated detached "
			    "deprecated autoconf temporary")];

	buf[0] = '\0';
	if (flags & IN6_IFF_ANYCAST)
		strlcat(buf, " anycast", sizeof(buf));
	if (flags & IN6_IFF_TENTATIVE)
		strlcat(buf, " tentative", sizeof(buf));
	if (flags & IN6_IFF_DUPLICATED)
		strlcat(buf, " duplicated", sizeof(buf));
	if (flags & IN6_IFF_DETACHED)
		strlcat(buf, " detached", sizeof(buf));
	if (flags & IN6_IFF_DEPRECATED)
		strlcat(buf, " deprecated", sizeof(buf));
	if (flags & IN6_IFF_AUTOCONF)
		strlcat(buf, " autoconf", sizeof(buf));
	if (flags & IN6_IFF_TEMPORARY)
		strlcat(buf, " temporary", sizeof(buf));

	return (buf);
}

void
frontend_startup(void)
{
	struct if_nameindex	*ifnidxp, *ifnidx;

	if ((ifnidxp = if_nameindex()) == NULL)
		fatalx("if_nameindex");

	for(ifnidx = ifnidxp; ifnidx->if_index !=0 && ifnidx->if_name != NULL;
	    ifnidx++)
		update_iface(ifnidx->if_index, ifnidx->if_name);

	if_freenameindex(ifnidxp);
	frontend_imsg_compose_main(IMSG_STARTUP_DONE, -1, NULL, 0);
}

void
route_receive(int fd, short events, void *arg)
{
	static uint8_t			 *buf;

	struct rt_msghdr		*rtm;
	struct sockaddr			*sa, *rti_info[RTAX_MAX];
	ssize_t				 n;

	if (buf == NULL) {
		buf = malloc(ROUTE_SOCKET_BUF_SIZE);
		if (buf == NULL)
			fatal("malloc");
	}
	rtm = (struct rt_msghdr *)buf;
	if ((n = read(fd, buf, ROUTE_SOCKET_BUF_SIZE)) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		log_warn("dispatch_rtmsg: read error");
		return;
	}

	if (n == 0)
		fatal("routing socket closed");

	if (n < (ssize_t)sizeof(rtm->rtm_msglen) || n < rtm->rtm_msglen) {
		log_warnx("partial rtm of %zd in buffer", n);
		return;
	}

	if (rtm->rtm_version != RTM_VERSION)
		return;

	sa = (struct sockaddr *)(buf + rtm->rtm_hdrlen);
	get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

	handle_route_message(rtm, rti_info);
}

void
handle_route_message(struct rt_msghdr *rtm, struct sockaddr **rti_info)
{
	struct if_msghdr		*ifm;
	struct if_announcemsghdr	*ifan;
	struct sockaddr_rtdns		*rtdns;
	struct sockaddr_in6		*sin6;
	struct iface			*iface;
	int				 xflags;
	char				 ifnamebuf[IFNAMSIZ];
	char				*if_name;

	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		if (if_name == NULL) {
			log_debug("RTM_IFINFO: lost if %d", ifm->ifm_index);
			remove_iface(ifm->ifm_index);
			break;
		}

		xflags = get_xflags(if_name);
		if (xflags == -1 || !(xflags & (IFXF_AUTOCONF6 |
		    IFXF_AUTOCONF6TEMP))) {
			log_debug("RTM_IFINFO: %s(%d) no(longer) "
			    "autoconf6", if_name, ifm->ifm_index);
			remove_iface(ifm->ifm_index);
		} else
			update_iface(ifm->ifm_index, if_name);
		break;
	case RTM_IFANNOUNCE:
		ifan = (struct if_announcemsghdr *)rtm;
		if (ifan->ifan_what == IFAN_DEPARTURE)
			remove_iface(ifan->ifan_index);
		break;
	case RTM_NEWADDR:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		if (if_name == NULL) {
			log_debug("RTM_NEWADDR: lost if %d", ifm->ifm_index);
			remove_iface(ifm->ifm_index);
			break;
		}
		log_debug("RTM_NEWADDR: %s[%u]", if_name, ifm->ifm_index);
		update_iface(ifm->ifm_index, if_name);
		break;
	case RTM_DELADDR:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		if (if_name == NULL) {
			log_debug("RTM_DELADDR: lost if %d", ifm->ifm_index);
			remove_iface(ifm->ifm_index);
			break;
		}

		if (rtm->rtm_addrs & RTA_IFA && rti_info[RTAX_IFA]->sa_family
		    == AF_INET6) {
			log_debug("RTM_DELADDR: %s[%u]", if_name,
			    ifm->ifm_index);
			update_iface(ifm->ifm_index, if_name);
		}
		break;
	case RTM_CHGADDRATTR:
		ifm = (struct if_msghdr *)rtm;
		if_name = if_indextoname(ifm->ifm_index, ifnamebuf);
		if (if_name == NULL) {
			log_debug("RTM_CHGADDRATTR: lost if %d",
			    ifm->ifm_index);
			remove_iface(ifm->ifm_index);
			break;
		}

		if (rtm->rtm_addrs & RTA_IFA && rti_info[RTAX_IFA]->sa_family
		    == AF_INET6) {
			sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];

			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				break;
			update_iface(ifm->ifm_index, if_name);
		}
		break;
	case RTM_PROPOSAL:
		if (!(rtm->rtm_addrs & RTA_DNS))
			break;

		rtdns = (struct sockaddr_rtdns*)rti_info[RTAX_DNS];
		switch (rtdns->sr_family) {
		case AF_INET:
			if ((rtdns->sr_len - 2) % sizeof(struct in_addr) != 0) {
				log_warnx("ignoring invalid RTM_PROPOSAL");
				return;
			}
			break;
		case AF_INET6:
			if ((rtdns->sr_len - 2) % sizeof(struct in6_addr) != 0) {
				log_warnx("ignoring invalid RTM_PROPOSAL");
				return;
			}
			iface = get_iface_by_id(rtm->rtm_index);
			if (iface == NULL)
				break;
			memcpy(&iface->rtdns, rtdns, sizeof(iface->rtdns));
			if (IN6_IS_ADDR_UNSPECIFIED(&iface->in6))
				break;
			handle_ipv6_resolvers(rtdns, rtm->rtm_index);
			break;
		default:
			log_warnx("ignoring invalid RTM_PROPOSAL");
			return;
		}

		break;
	default:
		log_debug("unexpected RTM: %d", rtm->rtm_type);
		break;
	}
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
}

struct iface*
get_iface_by_id(uint32_t if_index)
{
	struct iface	*iface;

	LIST_FOREACH (iface, &interfaces, entries) {
		if (iface->if_index == if_index)
			return (iface);
	}

	return (NULL);
}

void
remove_iface(uint32_t if_index)
{
	struct iface	*iface;

	iface = get_iface_by_id(if_index);

	if (iface == NULL)
		return;

	LIST_REMOVE(iface, entries);

	free(iface);

	update_clat(if_index);
}

void
handle_ipv6_resolvers(struct sockaddr_rtdns *rtdns, uint32_t if_index)
{
	struct sockaddr_in6	 sin6;
	struct dns_ctx		*dns_ctx;
	int			 rdns_count, i;
	char			*src, *resolv_conf = NULL, *tmp = NULL;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);

	src = rtdns->sr_dns;
	rdns_count = (rtdns->sr_len - offsetof(struct sockaddr_rtdns, sr_dns)) /
	    sizeof(struct in6_addr);

	for (i = 0; i < rdns_count; i++) {
		memcpy(&sin6.sin6_addr, src, sizeof(struct in6_addr));
		src += sizeof(struct in6_addr);
		if (IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr))
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr) ||
		    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6.sin6_addr))
			sin6.sin6_scope_id = if_index;
		tmp = resolv_conf;
		if (asprintf(&resolv_conf, "%snameserver %s\n", tmp ==
		    NULL ? "" : tmp, sin6_to_str(&sin6)) == -1) {
			log_warn(NULL);
			free(tmp);
			return;
		}
		free(tmp);
	}

	if (resolv_conf == NULL)
		return;

	if ((dns_ctx = calloc(1, sizeof(struct dns_ctx))) == NULL) {
		log_warn("%s: could not create dns_ctx", __func__);
		return;
	}

	dns_ctx->if_index = if_index;

	if ((dns_ctx->asr_ctx = asr_resolver_from_string(resolv_conf)) !=
	    NULL) {
		struct asr_query	*aq = NULL;
		struct addrinfo		 hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;

		aq = getaddrinfo_async("ipv4only.arpa", "53", &hints,
		    dns_ctx->asr_ctx);
		if (aq == NULL) {
			log_warn("%s: getaddrinfo_async", __func__);
			asr_resolver_free(dns_ctx->asr_ctx);
			free(dns_ctx);
		} else {
			event_asr_run(aq, check_dns64_done, dns_ctx);
		}
	} else {
		free(dns_ctx);
		log_warnx("%s: could not create asr context", __func__);
	}
}

void
check_dns64_done(struct asr_result *ar, void *arg)
{
	/* RFC 7050: ipv4only.arpa resolves to 192.0.0.170 and 192.9.0.171 */
	const uint8_t		 wka1[] = {192, 0, 0, 170};
	const uint8_t		 wka2[] = {192, 0, 0, 171};
	struct iface		*iface;
	struct addrinfo		*res;
	struct dns64_prefix	*prefixes = NULL;
	struct dns_ctx		*dns_ctx = arg;
	int			 i, dns64_found = 0, if_index;
	char			 ntopbuf[INET6_ADDRSTRLEN];

	if_index = dns_ctx->if_index;

	iface = get_iface_by_id(if_index);

	if (iface != NULL)
		iface->dns_done = 1;

	if (ar->ar_gai_errno != 0) {
		if (ar->ar_gai_errno != EAI_NODATA)
			log_warnx("%s: %s", __func__,
			    gai_strerror(ar->ar_gai_errno));
		goto out;
	}

	if (iface == NULL) {
		freeaddrinfo(ar->ar_addrinfo);
		goto out;
	}

	prefixes = calloc(ar->ar_count, sizeof(struct dns64_prefix));
	for (res = ar->ar_addrinfo; res; res = res->ai_next) {
		struct sockaddr_in6	*sin6;
		int			 preflen;

		if (res->ai_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)res->ai_addr;

		if ((preflen = dns64_preflen(&sin6->sin6_addr, wka1)) != -1)
			add_dns64_prefix(&sin6->sin6_addr, preflen, prefixes,
			    ar->ar_count, WKA1_FOUND);

		if ((preflen = dns64_preflen(&sin6->sin6_addr, wka2)) != -1)
			add_dns64_prefix(&sin6->sin6_addr, preflen, prefixes,
			    ar->ar_count, WKA2_FOUND);
	}

	for (i = 0; i < ar->ar_count && prefixes[i].flags != 0; i++) {
		if ((prefixes[i].flags & (WKA1_FOUND | WKA2_FOUND)) ==
		    (WKA1_FOUND | WKA2_FOUND)) {
			dns64_found = 1;
			if (!iface->dns64_enabled || iface->dns64_prefixlen
			    != prefixes[i].prefixlen ||
			    memcmp(&iface->dns64_prefix, &prefixes[i].in6,
			    sizeof(iface->dns64_prefix)) != 0) {
				log_debug("%s: %s/%d", __func__,
				    inet_ntop(AF_INET6, &prefixes[i].in6,
				    ntopbuf, sizeof(ntopbuf)),
				    prefixes[i].prefixlen);
				iface->dns64_enabled =1;
				iface->dns64_prefixlen = prefixes[i].prefixlen;
				memcpy(&iface->dns64_prefix, &prefixes[i].in6,
				    sizeof(iface->dns64_prefix));
				update_clat(iface->if_index);
			}
			break; /* we are only using the first prefix */
		}
	}
	freeaddrinfo(ar->ar_addrinfo);

 out:
	if (!dns64_found) {
		if (iface != NULL && iface->dns64_enabled) {
			iface->dns64_enabled = 0;
			memset(&iface->dns64_prefix, 0,
			    sizeof(iface->dns64_prefix));
			iface->dns64_prefixlen = 0;
		}
		update_clat(if_index);
	}
	asr_resolver_free(dns_ctx->asr_ctx);
	free(dns_ctx);
}

int
dns64_preflen(const struct in6_addr *in6, const uint8_t *wka)
{
	/* RFC 6052, 2.2 */
	static const int	 possible_prefixes[] = {32, 40, 48, 56, 64, 96};
	size_t			 i, j;
	int			 found, pos;

	for (i = 0; i < nitems(possible_prefixes); i++) {
		pos = possible_prefixes[i] / 8;
		found = 1;
		for (j = 0; j < 4 && found; j++, pos++) {
			if (pos == 8) {
				if (in6->s6_addr[pos] != 0)
					found = 0;
				pos++;
			}
			if (in6->s6_addr[pos] != wka[j])
				found = 0;
		}
		if (found)
			return possible_prefixes[i];
	}
	return -1;
}

void
add_dns64_prefix(const struct in6_addr *in6, int prefixlen,
    struct dns64_prefix *prefixes, int prefixes_size, int flag)
{
	struct in6_addr	 tmp;
	int		 i;

	tmp = *in6;

	for(i = prefixlen / 8; i < 16; i++)
		tmp.s6_addr[i] = 0;

	for (i = 0; i < prefixes_size; i++) {
		if (prefixes[i].flags == 0) {
			prefixes[i].in6 = tmp;
			prefixes[i].prefixlen = prefixlen;
			prefixes[i].flags |= flag;
			break;
		} else if (prefixes[i].prefixlen == prefixlen &&
		    memcmp(&prefixes[i].in6, &tmp, sizeof(tmp)) == 0) {
			prefixes[i].flags |= flag;
			break;
		}
	}
}

void
update_clat(uint32_t if_index) {
	struct iface		*iface;
	struct clat_imsg	 clat_imsg;
	char			 buf_in6[INET6_ADDRSTRLEN];
	char			 buf_dns64_prefix[INET6_ADDRSTRLEN];

	iface = get_iface_by_id(if_index);

	if (iface != NULL && iface->dns_done == 0)
		return;

	memset(&clat_imsg, 0, sizeof(clat_imsg));

	if (iface == NULL || !iface->dns64_enabled)
		log_debug("%s: disable clat", __func__);
	else {
		log_debug("%s: enable clat %s - %s/%d",
		    __func__, inet_ntop(AF_INET6, &iface->in6, buf_in6,
		    sizeof(buf_in6)),
		    inet_ntop(AF_INET6, &iface->dns64_prefix, buf_dns64_prefix,
		    sizeof(buf_dns64_prefix)), iface->dns64_prefixlen);
		clat_imsg.enable = 1;
		memcpy(&clat_imsg.from, &iface->in6, sizeof(clat_imsg.from));
		memcpy(&clat_imsg.to, &iface->dns64_prefix,
		    sizeof(clat_imsg.to));
		clat_imsg.prefixlen = iface->dns64_prefixlen;
	}
	frontend_imsg_compose_main(IMSG_CLAT, -1, &clat_imsg,
	    sizeof(clat_imsg));
}
