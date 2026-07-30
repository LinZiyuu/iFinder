/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_PAGING_IDENTITY_H_
#define _UE_PAGING_IDENTITY_H_

#include "FiveGSTmsi.hpp"

extern "C" {
#include "Ngap_UEPagingIdentity.h"
}

namespace oai::ngap {

class UePagingIdentity {
 public:
  UePagingIdentity();
  virtual ~UePagingIdentity();

  void set(
      const std::string& set_id, const std::string& pointer,
      const std::string& tmsi);
  void get(std::string& fiveGsTmsi) const;
  void get(std::string& set_id, std::string& pointer, std::string& tmsi) const;

  bool encode(Ngap_UEPagingIdentity_t& pdu) const;
  bool decode(const Ngap_UEPagingIdentity_t& pdu);

 private:
  FiveGSTmsi m_FiveGSTmsi;
};

}  // namespace oai::ngap

#endif
