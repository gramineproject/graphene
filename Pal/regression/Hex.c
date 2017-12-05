/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"
#include "hex.h"

int main() {
  char buf[17];
  uint32_t x = 0xefbeadde;
  pal_printf("Hex test 1 is %s\n", hex2str(&x, buf, 17));
  uint64_t y = 0xcdcdcdcdcdcdcdcd;
  pal_printf("Hex test 2 is %s\n", hex2str(&y, buf, 17));
  return 0;
}
