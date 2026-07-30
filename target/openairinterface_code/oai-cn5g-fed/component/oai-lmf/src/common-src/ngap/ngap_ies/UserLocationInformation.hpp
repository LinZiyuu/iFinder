/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _USER_LOCATION_INFORMATION_H_
#define _USER_LOCATION_INFORMATION_H_

#include <optional>

#include "UserLocationInformationEutra.hpp"
#include "UserLocationInformationN3iwf.hpp"
#include "UserLocationInformationNr.hpp"

extern "C" {
#include "Ngap_UserLocationInformation.h"
}

namespace oai::ngap {
class UserLocationInformation {
 public:
  UserLocationInformation();
  virtual ~UserLocationInformation();

  void set(const UserLocationInformationEutra&);
  bool get(UserLocationInformationEutra&) const;

  void set(const UserLocationInformationNr&);
  bool get(UserLocationInformationNr&) const;

  // void set(const UserLocationInformationN3IWF&);
  // void get(UserLocationInformationN3IWF&);

  Ngap_UserLocationInformation_PR getChoiceOfUserLocationInformation() const;

  bool encode(Ngap_UserLocationInformation_t& userLocationInformation) const;
  bool decode(const Ngap_UserLocationInformation_t& userLocationInformation);

 private:
  Ngap_UserLocationInformation_PR m_Present;
  std::optional<UserLocationInformationEutra> m_UserLocationInformationEutra;
  std::optional<UserLocationInformationNr> m_UserLocationInformationNr;
  // TODO: UserLocationInformationN3IWF *userLocationInformationN3IWF;
};

}  // namespace oai::ngap

#endif
