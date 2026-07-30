/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NON_3GPP_NW_PROVIDED_POLICIES_H
#define _NON_3GPP_NW_PROVIDED_POLICIES_H

#include "Type1NasIeFormatTv.hpp"

constexpr uint8_t kNon3gppNwProvidedPoliciesLength = 1;
constexpr auto kNon3gppNwProvidedPoliciesIeName =
    "Non-3GPP NW Provided Policies";

namespace oai::nas {

class Non3gppNwProvidedPolicies : public Type1NasIeFormatTv {
 public:
  Non3gppNwProvidedPolicies();
  Non3gppNwProvidedPolicies(uint8_t value);
  virtual ~Non3gppNwProvidedPolicies();

  static std::string GetIeName() { return kNon3gppNwProvidedPoliciesIeName; }

  void SetValue(uint8_t value);
  uint8_t GetValue() const;

 private:
};

}  // namespace oai::nas

#endif
