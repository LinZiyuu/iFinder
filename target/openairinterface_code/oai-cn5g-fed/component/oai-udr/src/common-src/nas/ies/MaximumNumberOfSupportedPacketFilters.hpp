/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_H
#define _MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_H

#include "Type3NasIe.hpp"

constexpr uint8_t kMaximumNumberOfSupportedPacketFiltersMinimumLength = 2;
constexpr uint8_t kMaximumNumberOfSupportedPacketFiltersMaximumLength = 3;

constexpr auto kMaximumNumberOfSupportedPacketFiltersIeName =
    "Maximum Number Of Supported Packet Filters";

namespace oai::nas {

class MaximumNumberOfSupportedPacketFilters : public Type3NasIe {
 public:
  MaximumNumberOfSupportedPacketFilters();
  MaximumNumberOfSupportedPacketFilters(uint8_t iei);
  MaximumNumberOfSupportedPacketFilters(uint8_t _iei, uint16_t value);
  virtual ~MaximumNumberOfSupportedPacketFilters();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kMaximumNumberOfSupportedPacketFiltersIeName;
  }
  uint32_t GetIeLength() const override;

  void Set(uint8_t _iei, uint16_t value);

  void SetValue(uint16_t value);
  uint16_t GetValue() const;

 private:
  uint16_t value_;
};

}  // namespace oai::nas

#endif
