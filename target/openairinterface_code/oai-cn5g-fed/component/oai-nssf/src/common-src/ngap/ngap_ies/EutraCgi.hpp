/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EUTRA_CGI_H_
#define _EUTRA_CGI_H_

#include "EutraCellIdentity.hpp"
#include "PlmnId.hpp"

extern "C" {
#include "Ngap_EUTRA-CGI.h"
}

namespace oai::ngap {

class EutraCgi {
 public:
  EutraCgi();
  virtual ~EutraCgi();

  void set(const PlmnId&, const EutraCellIdentity&);
  void get(PlmnId&, EutraCellIdentity&) const;

  bool encode(Ngap_EUTRA_CGI_t&) const;
  bool decode(const Ngap_EUTRA_CGI_t&);

 private:
  PlmnId m_PlmnId;                        // Mandatory
  EutraCellIdentity m_eutraCellIdentity;  // Mandatory
};
}  // namespace oai::ngap

#endif
