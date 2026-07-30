/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EAP_MESSAGE_H_
#define _EAP_MESSAGE_H_

#include "Type6NasIe.hpp"

constexpr uint8_t kEapMessageMinimumLength = 7;
constexpr uint8_t kEapMessageContentMinimumLength =
    kEapMessageMinimumLength - 3;  // Minimum length - 3 octets for IEI/Length
constexpr uint16_t kEapMessageMaximumLength = 1503;
constexpr auto kEapMessageIeName            = "EAP Message";

namespace oai::nas {

class EapMessage : public Type6NasIe {
 public:
  EapMessage();
  EapMessage(uint8_t iei);
  EapMessage(const bstring& eap);
  EapMessage(uint8_t iei, const bstring& eap);
  virtual ~EapMessage();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kEapMessageIeName; }

  void SetValue(const bstring& eap);
  void GetValue(bstring& eap) const;

 private:
  bstring eap_;
};

}  // namespace oai::nas

#endif
