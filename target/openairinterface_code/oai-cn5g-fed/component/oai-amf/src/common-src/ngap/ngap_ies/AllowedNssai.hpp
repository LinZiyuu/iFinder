/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALLOWED_NSSAI_H_
#define _ALLOWED_NSSAI_H_

#include <vector>

#include "SNssai.hpp"

constexpr uint8_t kAllowedSNSSAIMaxItems = 8;

extern "C" {
#include "Ngap_AllowedNSSAI.h"
}

namespace oai::ngap {

class AllowedNSSAI {
 public:
  AllowedNSSAI();
  virtual ~AllowedNSSAI();

  void set(const std::vector<SNssai>& list);
  void get(std::vector<SNssai>& list) const;

  bool encode(Ngap_AllowedNSSAI_t& allowedNssaiList) const;
  bool decode(const Ngap_AllowedNSSAI_t& allowedNssaiList);

 private:
  std::vector<SNssai> m_List;
};
}  // namespace oai::ngap
#endif
