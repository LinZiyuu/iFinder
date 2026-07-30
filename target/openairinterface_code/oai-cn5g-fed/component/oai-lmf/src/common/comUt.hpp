/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PRINT_BUFFER_H
#define _PRINT_BUFFER_H

#include <string>

#include "iostream"
#include "logger.hpp"
using namespace std;

void print_buffer(
    const string app, const string commit, uint8_t* buf, int len) {
  if (!app.compare("lmf_app")) cout << commit.c_str() << endl;
  Logger::lmf_server().debug(commit.c_str());

  for (int i = 0; i < len; i++) printf("%x ", buf[i]);
  printf("\n");
}

//------------------------------------------------------------------------------
void print_buffer(
    const string app, const string commit, const uint8_t* buf, int len) {
  if (!app.compare("lmf_app")) cout << commit.c_str() << endl;
  Logger::lmf_server().debug(commit.c_str());

  for (int i = 0; i < len; i++) printf("%x ", buf[i]);
  printf("\n");
}

void hexStr2Byte(const char* src, unsigned char* dest, int len) {
  short i;
  unsigned char hBy, lBy;
  for (i = 0; i < len; i += 2) {
    hBy = toupper(src[i]);
    lBy = toupper(src[i + 1]);
    if (hBy > 0x39)
      hBy -= 0x37;
    else
      hBy -= 0x30;
    if (lBy > 0x39)
      lBy -= 0x37;
    else
      lBy -= 0x30;
    dest[i / 2] = (hBy << 4) | lBy;
  }
}

#endif
