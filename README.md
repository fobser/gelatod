GELATOD(8) - System Manager's Manual

# NAME

**gelatod** - a CLAT configuration daemon

# SYNOPSIS

**gelatod**
\[**-dv**]

# DESCRIPTION

**gelatod**
is a CLAT (Customer-side transLATor) configuration daemon.
It is part of 464XLAT, an architecture for providing limited IPv4
connectivity across an IPv6-only network.
It detects the presence of a NAT64 translator in IPv6 only networks
and configures
pf(4)
to translate IPv4 packets into IPv6 packets for programs that do not work
with DNS64.

Because address family translation overrides the routing table, it's only
possible to use
**af-to**
in
pf(4)
on inbound rules.
To make this work with localy generated traffic
**gelatod**
requires two
pair(4)
interfaces in different routing domains and an IPv4 default route pointing
to the second
pair(4)
interface.

	ifconfig pair1 inet 192.0.0.4/29
	ifconfig pair2 rdomain 1
	ifconfig pair2 inet 192.0.0.1/29
	ifconfig pair1 patch pair2
	route add -host -inet default 192.0.0.1 -priority 48

Furthermore it needs an anchor in
pf(4)
called
**clat**
into which it will add address family translation rules.

For example, it will load rules like the following when it detects NAT64:

	pass in log quick on pair2 inet af-to inet6 \
	    from 2001:db8::da68:f613:4573:4ed0 to 64:ff9b::/96 \
	    rtable 0

The options are as follows:

**-d**

> Do not daemonize.
> If this option is specified,
> **gelatod**
> will run in the foreground and log to
> *stderr*.

**-v**

> Produce more verbose output.
> Multiple
> **-v**
> options increase the verbosity.

# SEE ALSO

pair(4),
pf(4),
hostname.if(5),
ifconfig(8),
slaacd(8)

# STANDARDS

M. Mawatari,
M. Kawashima, and
C. Byrne,
*464XLAT: Combination of Stateful and Stateless Translation*,
RFC 6877,
April 2013.

T. Savolainen,
J. Korhonen, and
D. Wing,
*Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis*,
RFC 7050,
November 2013.

# AUTHORS

The
**gelatod**
program was written by
Florian Obser &lt;[florian@openbsd.org](mailto:florian@openbsd.org)&gt;.

OpenBSD 7.0 - November 15, 2021
