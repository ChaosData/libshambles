CXX=clang++
CXXFLAGS=-std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -fPIC -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
SANITIZE=-fsanitize=address,undefined
DEBUG=-g -DDEBUG
OPTIMIZE=-O2
INCS=-I include -I vendor -I vendor/forge_socket
LINK=-Wl,-z,relro,-z,now,-z,noexecstack
OUTPUT=-shared -o lib/libshambles.so


default: build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	${CXX} ${CXXFLAGS} ${OPTIMIZE} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o

debug: build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${SANITIZE} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o

vdebug: build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/libforge_socket_override.o build/conntrack_delete.o build/conntrack_inject.o build/util.o

build/shambles.o: src/shambles.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/shambles.o -c src/shambles.cc

build/shambles_intercept.o: src/shambles_intercept.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/shambles_intercept.o -c src/shambles_intercept.cc

build/libforge_socket_override.o: src/libforge_socket_override/libforge_socket.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/libforge_socket_override.o -c src/libforge_socket_override/libforge_socket.cc

build/conntrack_delete.o: src/conntrack/delete.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/conntrack_delete.o -c src/conntrack/delete.cc

build/conntrack_inject.o: src/conntrack/inject.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/conntrack_inject.o -c src/conntrack/inject.cc

build/util.o: src/util.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/util.o -c src/util.cc

clean:
	rm lib/libshambles.so lib/libshambles.a build/*.o