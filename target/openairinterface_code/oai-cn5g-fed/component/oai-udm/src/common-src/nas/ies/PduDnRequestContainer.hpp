/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_DN_REQUEST_CONTAINER_H_
#define _PDU_DN_REQUEST_CONTAINER_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kPduDnRequestContainerMinimumLength = 3;
constexpr uint8_t kPduDnRequestContainerContentMinimumLength =
    kPduDnRequestContainerMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kPduDnRequestContainerMaximumLength = 255;
constexpr auto kPduDnRequestContainerIeName = "PDU DN Request Container";

namespace oai::nas {

class PduDnRequestContainer : public Type4NasIe {
 public:
  PduDnRequestContainer();
  PduDnRequestContainer(const bstring& PduDnRequestContainer);
  PduDnRequestContainer(bool iei);
  virtual ~PduDnRequestContainer();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kPduDnRequestContainerIeName; }

  void SetValue(const bstring& container);
  void GetValue(bstring& container) const;

 private:
  bstring pdu_dn_request_container_;
};

}  // namespace oai::nas

#endif
