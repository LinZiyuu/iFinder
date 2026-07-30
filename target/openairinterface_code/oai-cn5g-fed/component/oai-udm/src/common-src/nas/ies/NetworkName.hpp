/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NETWORK_NAME_H_
#define _NETWORK_NAME_H_

#include <stdint.h>

#include <string>

#include "Type4NasIe.hpp"
#include "bstrlib.h"

constexpr uint8_t kNetworkNameMinimumLength = 3;
constexpr uint8_t kNetworkNameContentMinimumLength =
    kNetworkNameMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kNetworkNameIeName = "Network Name";

namespace oai::nas {

class NetworkName : public Type4NasIe {
 public:
  NetworkName();
  NetworkName(uint8_t iei);
  virtual ~NetworkName();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return kNetworkNameIeName; }

  void SetIei(uint8_t iei);

  void SetCodingScheme(uint8_t value);
  // TODO: getCodingScheme

  void SetAddCI(uint8_t value);
  // TODO: getAddCI

  void SetNumberOfSpareBits(uint8_t value);
  // TODO: getNumberOfSpareBits

  void SetTextString(const std::string& str);
  void SetTextString(const bstring& str);

 private:
  // uint8_t iei_;
  // uint16_t length_;
  uint8_t coding_scheme_;         // octet 3
  uint8_t add_ci_;                // octet 3
  uint8_t number_of_spare_bits_;  // octet 3
  bstring text_string_;
};
}  // namespace oai::nas

#endif
