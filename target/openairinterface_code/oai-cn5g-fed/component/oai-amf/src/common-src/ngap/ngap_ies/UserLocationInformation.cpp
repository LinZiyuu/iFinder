/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UserLocationInformation.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UserLocationInformation::UserLocationInformation() {
  m_Present                      = Ngap_UserLocationInformation_PR_NOTHING;
  m_UserLocationInformationEutra = std::nullopt;
  m_UserLocationInformationNr    = std::nullopt;
  // userLocationInformationN3IWF = std::nullopt;
}

//------------------------------------------------------------------------------
UserLocationInformation::~UserLocationInformation() {}

//------------------------------------------------------------------------------
Ngap_UserLocationInformation_PR
UserLocationInformation::getChoiceOfUserLocationInformation() const {
  return m_Present;
}

//------------------------------------------------------------------------------
bool UserLocationInformation::get(
    UserLocationInformationEutra& userLocationInformation) const {
  if (!m_UserLocationInformationEutra.has_value()) return false;
  userLocationInformation = m_UserLocationInformationEutra.value();
  return true;
}

//------------------------------------------------------------------------------
void UserLocationInformation::set(
    const UserLocationInformationEutra& userLocationInformation) {
  m_Present = Ngap_UserLocationInformation_PR_userLocationInformationEUTRA;
  m_UserLocationInformationEutra =
      std::optional<UserLocationInformationEutra>(userLocationInformation);
}

//------------------------------------------------------------------------------
bool UserLocationInformation::get(
    UserLocationInformationNr& userLocationInformation) const {
  if (!m_UserLocationInformationNr.has_value()) return false;
  userLocationInformation = m_UserLocationInformationNr.value();
  return true;
}

//------------------------------------------------------------------------------
void UserLocationInformation::set(
    const UserLocationInformationNr& userLocationInformation) {
  m_Present = Ngap_UserLocationInformation_PR_userLocationInformationNR;
  m_UserLocationInformationNr =
      std::optional<UserLocationInformationNr>(userLocationInformation);
}

//------------------------------------------------------------------------------
bool UserLocationInformation::encode(
    Ngap_UserLocationInformation_t& userLocationInformation) const {
  userLocationInformation.present = m_Present;
  switch (m_Present) {
    case Ngap_UserLocationInformation_PR_userLocationInformationEUTRA: {
      Ngap_UserLocationInformationEUTRA* ie_eutra =
          (Ngap_UserLocationInformationEUTRA*) calloc(
              1, sizeof(Ngap_UserLocationInformationEUTRA));
      m_UserLocationInformationEutra.value().encode(*ie_eutra);
      userLocationInformation.choice.userLocationInformationEUTRA = ie_eutra;
      break;
    }
    case Ngap_UserLocationInformation_PR_userLocationInformationNR: {
      Ngap_UserLocationInformationNR* ie_nr =
          (Ngap_UserLocationInformationNR*) calloc(
              1, sizeof(Ngap_UserLocationInformationNR));
      m_UserLocationInformationNr.value().encode(*ie_nr);
      userLocationInformation.choice.userLocationInformationNR = ie_nr;
      break;
    }
    default:
      oai::logger::logger_common::ngap().warn(
          "UserLocationInformation encode error!");
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UserLocationInformation::decode(
    const Ngap_UserLocationInformation_t& userLocationInformation) {
  m_Present = userLocationInformation.present;
  switch (m_Present) {
    case Ngap_UserLocationInformation_PR_userLocationInformationEUTRA: {
      UserLocationInformationEutra user_location_information_eutra = {};
      user_location_information_eutra.decode(
          *userLocationInformation.choice.userLocationInformationEUTRA);
      m_UserLocationInformationEutra =
          std::optional<UserLocationInformationEutra>(
              user_location_information_eutra);
      break;
    }
    case Ngap_UserLocationInformation_PR_userLocationInformationNR: {
      UserLocationInformationNr user_location_information_nr = {};
      user_location_information_nr.decode(
          *userLocationInformation.choice.userLocationInformationNR);
      m_UserLocationInformationNr = std::optional<UserLocationInformationNr>(
          user_location_information_nr);
      break;
    }
    default:
      oai::logger::logger_common::ngap().warn(
          "UserLocationInformation decode error!");
      return false;
  }
  return true;
}

}  // namespace oai::ngap
