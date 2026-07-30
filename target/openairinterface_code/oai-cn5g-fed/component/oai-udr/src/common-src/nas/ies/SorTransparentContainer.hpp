/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SOR_TRANSPARENT_CONTAINER_HPP_
#define _SOR_TRANSPARENT_CONTAINER_HPP_

#include "Type6NasIe.hpp"

constexpr uint8_t kSorTransparentContainerMinimumLength = 20;
constexpr uint8_t kSorTransparentContainerContentMinimumLength =
    kSorTransparentContainerMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint8_t kSorTransparentContainerIeMacLength = 16;
constexpr auto kSorTransparentContainerIeName = "SOR Transparent Container";

namespace oai::nas {

class SorTransparentContainer : public Type6NasIe {
 public:
  SorTransparentContainer();
  SorTransparentContainer(
      uint8_t header,
      const uint8_t (&value)[kSorTransparentContainerIeMacLength]);
  virtual ~SorTransparentContainer();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kSorTransparentContainerIeName; }

  void GetValue(uint8_t (&value)[kSorTransparentContainerIeMacLength]) const;

 private:
  uint8_t header_;
  uint8_t sor_mac_i_[kSorTransparentContainerIeMacLength];
  std::optional<uint8_t> counter_;
  // Other IEs
};

}  // namespace oai::nas

#endif
