clang++ -std=c++14 -Wall -Wextra -pedantic -fsanitize=address,undefined -g -o test \
        tester.cc interception.cc util.cc libforge_socket/libforge_socket.cc

