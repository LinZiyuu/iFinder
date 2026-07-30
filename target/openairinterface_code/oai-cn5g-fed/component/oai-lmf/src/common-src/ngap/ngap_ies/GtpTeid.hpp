/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GTP_TEID_H_
#define _GTP_TEID_H_

extern "C" {
#include "Ngap_GTP-TEID.h"
}

namespace oai::ngap {

class GtpTeid {
 public:
  GtpTeid();
  virtual ~GtpTeid();

  void set(const uint32_t gtpTeid);
  bool get(uint32_t& gtpTeid) const;

  bool encode(Ngap_GTP_TEID_t& gtpTeid) const;
  bool decode(const Ngap_GTP_TEID_t& gtpTeid);

 private:
  uint32_t m_GtpTeid;
};

}  // namespace oai::ngap

#endif
