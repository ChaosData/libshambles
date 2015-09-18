# Overview

libshambles is a TCP interception library that hooks established TCP streams
and provides `send(2)`/`recv(2)`-able socket interfaces to communicate with the
connection's peers. It was primarily developed to intercept highly dynamic
network protocols at scale.

libshambles is designed to be minimal and allow the use of privilege
minimization and separation, and sandboxing techniques and technologies. Once
passed sufficient information about a TCP stream to intercept, libshambles will
generate sockets with forged TCP state data so as to trick the kernel into
recognizing the stream's packets as ones intended for it. It then modifies the
firewall and connection tracking state to cleanly split the client-to-server
connection into two separate ones, client-to-interceptor and
interceptor-to-server. It additionally contains code to pass the sockets to
other processes via Unix domain sockets and also contains teardown
functionality to undo the firewall modifications once the intercepted
connection is finished.

libshambles is written in C++ (compiled as C++14), but exports its public API
bindings as C. It is mostly released under the two-clause BSD license, but due
to its current dependence on a Linux kernel module and netfilter, compiled
binaries will be encumbered by the GPLv2.

# Quickstart

As libshambles is a library and also needs to be supplied accurate TCP/IP
connection information (e.g. IP addresses, ports, SEQ/ACK numbers), the
libshambles codebase is highly limited. However, a sample toolchain leveraging
libshambles is provided that consists of a libpcap daemon, an interceptor using
libshambles, and Python/Ruby scripts wrapping a native (C++14) file descriptor
accepting daemon. These tools are provided in the `samples` directory.


```bash
$ git clone <FILL IN>/libshambles
$ git submodule init
$ git submodule update
$ cd vendor/forge_socket
$ make
$ sudo insmod forge_socket.ko
$ cd ../../
$ make
```

```bash
$ cd samples/shambles
$ sh setup_libuv.sh
$ make
$ mkdir /tmp/shambles
$ sudo ./shambles <external IP> <internal IP> <LAN netmask> /tmp/shambles/shambles_sock
```

```bash
$ cd /path/to/libshambles
$ cd samples/scan
$ make
$ sudo ./scan <internal interface> '<bpf filter>' '<search regex>' '127.0.0.1' '5555'
```

```bash
$ cd /path/to/libshambles
$ cd samples/hookffi
$ make
$ nano hook.py # add in whatever you want to the custom_hook function
$ python hook.py /tmp/shambles/shambles_sock root
```

Next, try using a plaintext TCP connection that will match both the bpf filter
and search regex passed to the `scan` daemon, and observe that your python code
will intercept the connection and read and write whatever your wanted to either
side of the stream.


# Dependencies

libshambles itself has a couple of dependencies on netfilter stuff and the
samples depend on some other things like libpcap and libuv. Additionally, as
I've been developing libshambles on Ubuntu 14.04, it relies on Clang and libc++
for modern C++ support needed to compile and run it.

On Ubuntu 14.04, the below `apt-get` one-liner should get you most of the way
there.
```bash
$ sudo apt-get install build-essential git libpcap-dev libmnl-dev libnetfilter-conntrack3 libcap-dev libc++-dev libc++abi1 libc++1 libnetfilter-conntrack-dev libtool automake autotools-dev
```
You'll also need to grab Clang from the LLVM
[releases page](http://llvm.org/releases/download.html). I'm lazy, so I just
extract it out to `/opt/clangllvm` on my machine and then prepend that to my
`$PATH`, but do as you like.

Other dependencies are covered in the above quickstart instructions.
