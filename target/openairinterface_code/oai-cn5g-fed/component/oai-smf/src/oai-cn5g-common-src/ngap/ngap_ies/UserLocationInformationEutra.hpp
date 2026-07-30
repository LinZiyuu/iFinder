/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _USER_LOCATION_INFORMATION_EUTRA_H_
#define _USER_LOCATION_INFORMATION_EUTRA_H_

#include "EutraCgi.hpp"
#include "Tai.hpp"

extern "C" {
#include "Ngap_UserLocationInformationEUTRA.h"
}

namespace oai::ngap {
class UserLocationInformationEutra {
 public:
  UserLocationInformationEutra();
  virtual ~UserLocationInformationEutra();

  void set(const EutraCgi& eutraCgi, const Tai& tai);
  void get(EutraCgi& eutraCgi, Tai& tai) const;

  // bool getTimeStampPresence();

  bool encode(
      Ngap_UserLocationInformationEUTRA_t& userLocationInformation) const;
  bool decode(
      const Ngap_UserLocationInformationEUTRA_t& userLocationInformation);

 private:
  EutraCgi m_EutraCgi;  // Mandatory
  Tai m_Tai;            // Mandatory
  // TODO: TimeStamp *timeStamp; //Age of Location (Optional)
  // TODO: NG-RAN CGI (PSCell Information) (Optional)
};

}  // namespace oai::ngap

#endif
