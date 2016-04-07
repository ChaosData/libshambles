#include <stdio.h>

static char foo[] = "yo dawg";

char* test(char* msg) {
  puts(msg);
  return foo;
}
