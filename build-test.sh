clang++ -std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -g -o test \
  tester.ccinterception.cc util.cc libforge_socket/libforge_socket.cc \
  conntrack/delete.cc conntrack/inject.cc libintercept.cc \
  -lnetfilter_conntrack
