/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_IE_H_
#define _NAS_IE_H_

#include <stdint.h>
#include <optional>
#include <vector>

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

extern "C" {
#include "TLVDecoder.h"
#include "TLVEncoder.h"
#include "bstrlib.h"
}

namespace oai::nas {

class NasIe {
 public:
  NasIe();
  virtual ~NasIe() = default;

  virtual int Encode(uint8_t* buf, int len) const = 0;
  virtual int Decode(
      const uint8_t* const buf, int len, bool is_option = false) = 0;

  virtual uint32_t GetIeLength() const = 0;

  virtual bool Validate(int len) const = 0;

 protected:
};

}  // namespace oai::nas

#endif
