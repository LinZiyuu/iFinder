/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_MESSAGE_CONTAINER_H_
#define _NAS_MESSAGE_CONTAINER_H_

#include "Type6NasIe.hpp"

constexpr uint8_t kNasMessageContainerMinimumLength = 3;
constexpr uint8_t kNasMessageContainerContentMinimumLength =
    kNasMessageContainerMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint32_t kNasMessageContainerMaximumLength = 65535;
constexpr auto kNasMessageContainerIeName            = "NAS Message Container";

namespace oai::nas {

class NasMessageContainer : public Type6NasIe {
 public:
  NasMessageContainer();
  NasMessageContainer(const bstring& value);
  virtual ~NasMessageContainer();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kNasMessageContainerIeName; }

  void GetValue(bstring& value) const;

 private:
  bstring value_;
};

}  // namespace oai::nas

#endif
