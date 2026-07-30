/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "utils.hpp"

#include "common_defs.h"
#include "logger_base.hpp"

#include <stdlib.h>

extern "C" {
#include "assertions.h"
#include "backtrace.h"
}
using namespace oai::utils;

//------------------------------------------------------------------------------
void utils::free_wrapper(void** ptr) {
  // for debug only
  AssertFatal(ptr, "Trying to free NULL ptr");
  if (ptr) {
    free(*ptr);
    *ptr = NULL;
  }
}

//------------------------------------------------------------------------------
void utils::bdestroy_wrapper(bstring* b) {
  if ((b) && (*b)) {
    bdestroy(*b);
    *b = NULL;
  }
}
