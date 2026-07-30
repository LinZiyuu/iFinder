/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NR_CGI_H_
#define _NR_CGI_H_

#include "NgapIesStruct.hpp"
#include "NrCellIdentity.hpp"
#include "PlmnId.hpp"

extern "C" {
#include "Ngap_NR-CGI.h"
}

namespace oai::ngap {

class NrCgi {
 public:
  NrCgi();
  virtual ~NrCgi();

  void set(const PlmnId&, const NrCellIdentity&);
  void get(PlmnId&, NrCellIdentity&) const;

  void set(
      const std::string& mcc, const std::string& mnc,
      const uint64_t& nrCellIdentity);

  void set(const struct NrCgi_s& cig);
  void get(struct NrCgi_s& cig) const;

  bool encode(Ngap_NR_CGI_t&) const;
  bool decode(const Ngap_NR_CGI_t&);

 private:
  PlmnId m_PlmnId;                  // Mandatory
  NrCellIdentity m_NrCellIdentity;  // Mandatory
};
}  // namespace oai::ngap

#endif
