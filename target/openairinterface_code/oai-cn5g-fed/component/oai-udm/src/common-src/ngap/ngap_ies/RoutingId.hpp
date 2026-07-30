/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ROUTING_ID_H_
#define _ROUTING_ID_H_

extern "C" {
#include "Ngap_RoutingID.h"
}

namespace oai::ngap {

class RoutingId {
 public:
  RoutingId();
  virtual ~RoutingId();

  void set(const OCTET_STRING_t& id);
  void get(OCTET_STRING_t& id) const;

  void encode(Ngap_RoutingID_t&) const;
  void decode(const Ngap_RoutingID_t&);

 private:
  OCTET_STRING_t m_RoutingId;  // Mandatory
};

}  // namespace oai::ngap

#endif
