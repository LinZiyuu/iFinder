/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EPS_NAS_MESSAGE_CONTAINER_H_
#define _EPS_NAS_MESSAGE_CONTAINER_H_

#include "Type6NasIe.hpp"

constexpr uint8_t kEpsNasMessageContainerMinimumLength = 4;
constexpr uint8_t kEpsNasMessageContainerContentMinimumLength =
    kEpsNasMessageContainerMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint8_t kEpsNasMessageContainer    = 253;
constexpr auto kEpsNasMessageContainerIeName = "EPS NAS Message Container";

namespace oai::nas {

class EpsNasMessageContainer : public Type6NasIe {
 public:
  EpsNasMessageContainer();
  EpsNasMessageContainer(const bstring& value);
  virtual ~EpsNasMessageContainer();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kEpsNasMessageContainerIeName; }

  // TODO: SetValue(const bstring& value)
  void GetValue(bstring& value) const;

 private:
  bstring value_;
};

}  // namespace oai::nas

#endif
