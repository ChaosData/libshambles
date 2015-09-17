clang++ -std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -g \
  -I testing/libuv/include -lpthread -D_GNU_SOURCE -o newtest \
  newtest.cc interception.cc util.cc libforge_socket/libforge_socket.cc \
  conntrack/delete.cc conntrack/inject.cc libintercept.cc \
  testing/libuv/out/Debug/libuv.a \
  -lnetfilter_conntrack -lcap

