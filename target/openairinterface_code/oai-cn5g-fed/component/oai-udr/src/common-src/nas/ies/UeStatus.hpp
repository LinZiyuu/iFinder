/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_STATUS_H_
#define _UE_STATUS_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kUeStatusIeLength = 3;
constexpr uint8_t kUeStatusIeContentLength =
    kUeStatusIeLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kUeStatusIeName = "UE Status";

namespace oai::nas {

class UeStatus : public Type4NasIe {
 public:
  UeStatus();
  UeStatus(bool n1, bool s1);
  virtual ~UeStatus();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kUeStatusIeName; }

  void SetN1(bool value);
  bool GetN1() const;

  void SetS1(bool value);
  bool GetS1() const;

 private:
  bool n1_;
  bool s1_;
};
}  // namespace oai::nas

#endif
