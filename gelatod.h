/*	$OpenBSD$	*/

/*
 * Copyright (c) 2017, 2021 Florian Obser <florian@openbsd.org>
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

#define	_PATH_LOCKFILE		"/dev/gelatod.lock"
#define GELATOD_USER		"_gelatod"

#define	IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_SOCKET_IPC,
	IMSG_STARTUP,
	IMSG_STARTUP_DONE,
	IMSG_CLAT,
};

struct clat_imsg {
	struct in6_addr  from;
	struct in6_addr  to;
	int		 prefixlen;
	int		 enable;
};

/* gelatod.c */
void		imsg_event_add(struct imsgev *);
int		imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
		    int, void *, uint16_t);
const char	*sin6_to_str(struct sockaddr_in6 *);

/* frontend.c */
void		 frontend(int, int);
