/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SSC_MODE_H_
#define _SSC_MODE_H_

#include "Type1NasIe.hpp"

constexpr auto kSscModeName = "SSC Mode";

namespace oai::nas {

class SscMode : public Type1NasIe {
 public:
  SscMode();
  SscMode(uint8_t type);
  SscMode(uint8_t iei, uint8_t type);
  virtual ~SscMode();

  static std::string GetIeName() { return kSscModeName; }

  void Set(bool high_pos);

  void SetSscMode(uint8_t value);
  uint8_t GetSscMode();

 private:
  void SetValue() override;
  void GetValue() override;
  uint8_t ssc_mode_;  // 3 bits
};

}  // namespace oai::nas

#endif
