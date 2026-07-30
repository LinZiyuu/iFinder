/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REGISTRATION_COMPLETE_H_
#define _REGISTRATION_COMPLETE_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class RegistrationComplete : public Nas5gmmMessage {
 public:
  RegistrationComplete();
  ~RegistrationComplete();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetSorTransparentContainer(
      uint8_t header,
      const uint8_t (&value)[kSorTransparentContainerIeMacLength]);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  std::optional<SorTransparentContainer>
      ie_sor_transparent_container_;  // Optional
};

}  // namespace oai::nas

#endif
