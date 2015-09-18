Title: libshambles: Efficiently Hooking Established TCP Connections

For a while now, I've been dealing with some highly complex and dynamic
protocols, several of which are used in distributed systems and peer-to-peer
networks. One thing that was a big hindrance in testing these protocols was
the fact that many of the important connections may appear somewhat random due
to the use of more secure communications to transfer host/peer connection
metadata. In particular, some protocols don't directly use TLS, or they perform
TLS/other crypto without authentication, and essentially rely on the apparent
unpredictability of the connection to prevent interception, or interception at
scale. In general, most TCP interception tools rely on prior knowledge about
what type of connection is going to be made, and only work by catching the
initial TCP handshake and having the client connect directly to the
interceptor/proxy. When such information is not available, tools tend to rely
on intercepting **ALL** connection attempts and proxying them to their intended
destinations. Needless to say, that doesn't really scale.

libshambles, now available
[here](FILLIN),
is a new library that enables one to hook live TCP connections that are already
routing through your (Linux) host. When provided with information about a
particular TCP connection (and some host network interface information), it
will split a targeted live TCP connection into two `send(2)`/`recv(2)`-able
sockets that communicate to the individual hosts of the targeted stream.


# Concept
libshambles is one of two core approaches to at-scale traffic interception,
though both are essentially the same. You can either build a TCP reassembly
engine on top of libpcap or you can try to leverage the one in your OS. I
based libshambles on the latter, because TCP is **really** complicated (just
the three-way handshake is simple), and I'm also lazy. And then on top of that,
new features are still being added to TCP, and maintaining a TCP engine is
probably more work than building one in the first place. But I digress, nothing
is fundamentally wrong with either option, and they both have their pros and
cons.

At its core, libshambles relies on a kernel module
([https://github.com/ewust/forge_socket](https://github.com/ewust/forge_socket))
to inject fake socket data into the
kernel's TCP state. This then tricks the OS into recognizing packets from a
targeted stream as being for it. There's a little more magic to it than that
that involves manipulating the netfilter connection tracking state and adding
in some `iptables` rules to do some packet massaging, but libshambles itself is
actually pretty small. Most of the heavy lifting in any system leveraging
libshambles will likely occur in the protocol signature/traffic recognizer code
that passes the necessary connection information to libshambles.

While I'm not sure if this is all that innovative, I did try to find other
projects that behaved similarly, but I came up dry.
[Divert sockets](https://www.freebsd.org/cgi/man.cgi?query=divert)
operate at the individual packet level and provide no stream abstractions as
part of their API. Heck, even the NSA copped out and apparently implemented a
[racing](http://blog.fox-it.com/2015/04/20/deep-dive-into-quantum-insert/)
[packet](http://arstechnica.com/information-technology/2013/11/quantum-of-pwnness-how-nsa-and-gchq-hacked-opec-and-others/)
[injector](https://www.schneier.com/blog/archives/2013/10/how_the_nsa_att.html)
instead of doing it this way. Of course, they chose to leverage a vastly
different sort of
[architecture](https://www.eff.org/files/2014/04/09/20140312-intercept-quantum_insert_diagrams.pdf)
that probably isn't super conducive to the way libshambles works; and they
supposedly just use it to go after plaintext HTTP.

However, libshambles does have its benefits. Unlike, QUANTUM INSERT, which
is
[trivially detectable](http://blog.fox-it.com/2015/04/20/deep-dive-into-quantum-insert/)
due to the victim receiving two different packets packets vying for the next spot
in the stream, libshambles is theoretically **much** harder to detect. If you
have an infrastructure where you can ensure that the hosts' packets always
route through the libshambles interceptor host, you can generally ensure that
no extraneous packets are received by either host.


# Architecture
libshambles is designed as a simple library that just performs the connection
intercept to generate a split-stream socket pair. It is intended to be as
general and simple a library as possible to enable the creation of all manner
of tools and frameworks. In general, however, libshambles is designed to easily
allow the use of privilege minimization and separation, and sandboxing
techniques and technologies.

## Traffic Scanner
libshambles is designed to enable the high-performance requirements of a SPAN
port listening PCAP daemon that performs traffic analysis. In these situations,
the listener itself does not operate on a system that can prevent the
"interesting" packets from passing through the router. However, libshambles
would work just as well on a non-10/40Gbit router that uses divert sockets as
a means to stop the "interesting" packets from even reaching the intended host.
However, regardless of the architecture used, **something** needs to pass the
TCP connection data (including the SEQ/ACK numbers) to libshambles. A very
simple PCAP listener that communicates with the sample libshambles interceptor
is included in the
[`samples/scan`](FILLIN)
directory of the repo.

## libshambles Interceptor
In addition to (or as part of) a traffic scanner, libshambles itself needs to
be used by some process on the router that has the `CAP_NET_ADMIN` and
`CAP_NET_RAW` capabilities. In theory, such a program could be implemented in
just about any manner and the design will likely be dictated primarily by
the design of the chosen architecture... and maybe taste. As part of the
libshambles release, I've included a sample interceptor in
[samples/shambles](FILLIN) that is libuv-based. A threaded implementation might
in-general have lower latency on the data submission from a PCAP listener to
the interceptor, but I haven't specifically tried to optimize the sample
toolchain.

## Protocol-Specific Proxy
libshambles contains code to pass the forged sockets to a separate process via
Unix domain sockets. What you pass them to is up to you as long as it's on the
same host. Within
[samples/hookscripts](fillin),
I've included a shared library and some scripts (Python/ctypes and Ruby/ffi)
that wrap the library to create in-language socket objects from the passed file
descriptors. For my own sanity, I've implemented the shared library to run a
forking Unix domain socket daemon, but this is mostly for simplicity.

For architectures where on-router must be kept to an even smaller minimum,
using a native Unix domain socket-to-TCP bridge and forwarding traffic to a
separate host will likely be more performant.


# Using libshambles

Well... that's up to you, but the general guidelines listed above are meant to
help. libshambles on its own, doesn't do a heck of a lot, and it requires all
sorts of other tooling to be in place to even use it. That's mostly why I've
included the sample toolchain, because I don't expect anyone to jump through 6
more hoops just to play with the code. So while you should feel free to hack on
the samples, they're meant to be simple (OK, the libuv one is complicated, but
that's mostly because it's evented) and hackable, and probably are not any sort
of production ready. But if you happen to find any bugs in the little
functionality that is implemented in the samples, please create an issue (and
maybe even a pull request if you have the time). If you happen to find any
security issues, please drop me a line at `jeff.dileo@nccgroup.trust` (my PGP
key is available [here](https://isecpartners.github.io/keys/jdileo.asc)).

## Performance Hearsay

I don't have a bunch of fancy, and likely misleading, numbers/graphs to display
here, but I can say that I'm currently able to race echo servers when the
"signaling" packet is sent from the internal network to an outside host. When
it's the outside host that sends the flagging packet, I lose the race (causing
a somewhat detectable double packet event), but I'm still able to get the
internal host onto my socket. They will just only ignore the first several
bytes (specifically the payload size of the "winning" legitimate packet) of the
and read in the following bytes as part of its `recv(2)`. This can probably be
beaten using one or multiple of the following:
- using better hardware (I'm literally running this in a VM where the external
  interface is bridged to a gigabit NIC and the internal interface is a 10/100
  USB NIC out to a separate physical machine).
- introducing an artificial delay between the external and internal interface
  (on my current setup, I'm losing the "race" at the sub-millisecond scale, so
  5-10ms of delay is probably a pretty sizable breathing room).
- configure your PCAP listener to be slightly more protocol aware and tweak the
  SEQ/ACK numbers to account for being unable to win the race.

# Future Work

Based on the results I've been able to achieve so far with libshambles, there
are definitely a few things I have in mind to add/implement in future versions.
Primarily, these include FreeBSD support (which will likely require creating a
`forge_socket`-alike among other changes to support the different firewall
stack) and researching weaknesses in the design (and more specifically the
current implementation) from a detection perspective. There are likely some
shell games to be played with identifying subtleties in TCP engine differences
between different operating systems and (especially) non-connection breaking
changes to packet fields/socket state like window sizes, which are not
currently being copied into the forged sockets. I'll also try to see if I can
integrate it (or at least a libshambles client) into the venerable
[Net Sensor](https://isis.poly.edu/~bk/netsensor/) codebase.

