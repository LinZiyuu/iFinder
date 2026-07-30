/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _USER_LOCATION_INFORMATION_NR_H_
#define _USER_LOCATION_INFORMATION_NR_H_

#include "NrCgi.hpp"
#include "Tai.hpp"

extern "C" {
#include "Ngap_UserLocationInformationNR.h"
}

namespace oai::ngap {
class UserLocationInformationNr {
 public:
  UserLocationInformationNr();
  virtual ~UserLocationInformationNr();

  void set(const NrCgi&, const Tai&);
  void get(NrCgi&, Tai&) const;

  bool encode(Ngap_UserLocationInformationNR_t&) const;
  bool decode(const Ngap_UserLocationInformationNR_t&);

 private:
  NrCgi m_NrCgi;  // Mandatory
  Tai m_Tai;      // Mandatory
  // bool timeStampIsSet;
  // TODO: TimeStamp timeStamp; //Age of Location (Optional)
  // TODO: PSCell Information
};

}  // namespace oai::ngap

#endif
