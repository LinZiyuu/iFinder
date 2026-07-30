/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MICO_MODE_INDICATION_H_
#define _MICO_MODE_INDICATION_H_

extern "C" {
#include "Ngap_MICOModeIndication.h"
}

namespace oai::ngap {

class MicoModeIndication {
 public:
  MicoModeIndication();
  virtual ~MicoModeIndication();

  void set(const long& micoModeIndication);
  void get(long& micoModeIndication) const;

  bool encode(Ngap_MICOModeIndication_t& micoModeIndication) const;
  bool decode(const Ngap_MICOModeIndication_t& micoModeIndication);

 private:
  long m_MicoModeIndication;
};

}  // namespace oai::ngap

#endif
