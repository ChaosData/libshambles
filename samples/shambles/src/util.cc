#include "util.h"

#include <stdio.h>
#include <string.h>

uint8_t parse_ipv4(const char* str, uint64_t len){
  uint8_t digits = 0;
  uint8_t vals[3] = { 0,0,0 };
  uint8_t dots = 0;
  uint16_t seg = 0;
  for (uint64_t i = 0; i < len; i++) {
    char c = str[i];
    if ('0' <= c && c <= '9') {
      vals[digits] = (uint16_t)c ^ 0x30;
      digits++;
      if (digits > 3) {
        return 1;
      }
    } else if (c == '.') {
      if (i+1 == len || dots == 3) {
        return 2;
      }
      if (digits == 1) {
        seg = vals[0];
      } else if (digits == 2) {
        seg = vals[0]*10 + vals[1];
      } else if (digits == 3) {
        seg = vals[0]*100 + vals[1]*10 + vals[2];
      }

      if (seg > 255) {
        return 3;
      }
      digits = 0; seg = 0;
      dots++;
      if (dots > 3) {
        return 4;
      }
    } else {
      return 5;
    }
  }
  if (dots == 3) {
    return 0;
  }
  return 6;
}

char* inet_htoa_r(char* buf, uint32_t haddr) {
  snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu",
    (uint8_t)((haddr >> 24) & 0xff),
    (uint8_t)((haddr >> 16) & 0xff),
    (uint8_t)((haddr >> 8) & 0xff),
    (uint8_t)(haddr & 0xff)
  );
  return buf;
}

char* inet_ntoa_r(char* buf, uint32_t haddr) {
  snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu",
    (uint8_t)((haddr) & 0xff),
    (uint8_t)((haddr >> 8) & 0xff),
    (uint8_t)((haddr >> 16) & 0xff),
    (uint8_t)((haddr >> 24) & 0xff)
  );
  return buf;
}

