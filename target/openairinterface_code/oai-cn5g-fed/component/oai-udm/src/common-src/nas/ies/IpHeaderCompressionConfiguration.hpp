/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _IP_HEADER_COMPRESSION_CONFIGURATION_H_
#define _IP_HEADER_COMPRESSION_CONFIGURATION_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kIpHeaderCompressionConfigurationMinimumLength = 5;
constexpr uint8_t kIpHeaderCompressionConfigurationContentMinimumLength =
    kIpHeaderCompressionConfigurationMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint16_t kIpHeaderCompressionConfigurationMaximumLength = 257;
constexpr auto kIpHeaderCompressionConfigurationIeName =
    "IP Header Compression Configuration";

namespace oai::nas {

class IpHeaderCompressionConfiguration : public Type4NasIe {
 public:
  IpHeaderCompressionConfiguration();
  IpHeaderCompressionConfiguration(uint8_t iei);
  virtual ~IpHeaderCompressionConfiguration();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() {
    return kIpHeaderCompressionConfigurationIeName;
  }

  void SetOctet3(uint8_t octet3);
  uint8_t GetOctet3() const;

  void SetMaxCid(uint16_t max_cid);
  uint16_t GetMaxCid() const;

  // TODO: Getter/setter for the rest

 private:
  uint8_t octet3_;
  uint16_t max_cid_;                                       // octet4, octet5
  std::optional<uint8_t> _context_setup_parameters_type_;  // octet 6
  bstring context_setup_parameters_container_;             // octet 7-n
};

}  // namespace oai::nas

#endif
