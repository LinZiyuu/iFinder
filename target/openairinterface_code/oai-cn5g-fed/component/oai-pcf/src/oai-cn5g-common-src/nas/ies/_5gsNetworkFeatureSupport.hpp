/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GS_NETWORK_FEATURE_SUPPORT_H
#define _5GS_NETWORK_FEATURE_SUPPORT_H

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsNetworkFeatureSupportMinimumLength = 3;
constexpr uint8_t k5gsNetworkFeatureSupportContentMinimumLength =
    k5gsNetworkFeatureSupportMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t k5gsNetworkFeatureSupportMaximumLength = 5;
constexpr auto k5gsNetworkFeatureSupportIeName = "5GS Network Feature Support";

namespace oai::nas {

class _5gsNetworkFeatureSupport : public Type4NasIe {
 public:
  _5gsNetworkFeatureSupport();
  _5gsNetworkFeatureSupport(uint8_t value);
  _5gsNetworkFeatureSupport(uint8_t value, uint8_t value2);
  virtual ~_5gsNetworkFeatureSupport();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return k5gsNetworkFeatureSupportIeName; }

  void SetValue(uint8_t value, uint8_t value2);
  // uint8_t GetValue() const;

 private:
  uint8_t value_;
  uint8_t value2_;
  // Spare
};

}  // namespace oai::nas

#endif
