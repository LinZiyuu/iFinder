/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UserLocationInformationEutra.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UserLocationInformationEutra::UserLocationInformationEutra() {}

//------------------------------------------------------------------------------
UserLocationInformationEutra::~UserLocationInformationEutra() {}

//------------------------------------------------------------------------------
void UserLocationInformationEutra::set(
    const EutraCgi& eutraCgi, const Tai& tai) {
  m_EutraCgi = eutraCgi;
  m_Tai      = tai;
}

//------------------------------------------------------------------------------
void UserLocationInformationEutra::get(EutraCgi& eutraCgi, Tai& tai) const {
  eutraCgi = m_EutraCgi;
  tai      = m_Tai;
}

//------------------------------------------------------------------------------
bool UserLocationInformationEutra::encode(
    Ngap_UserLocationInformationEUTRA_t& userLocationInformation) const {
  if (!m_EutraCgi.encode(userLocationInformation.eUTRA_CGI)) {
    oai::logger::logger_common::ngap().warn("Encode eUTRA_CGI IE error");
    return false;
  }
  if (!m_Tai.encode(userLocationInformation.tAI)) {
    oai::logger::logger_common::ngap().warn("Encode Tai IE error");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UserLocationInformationEutra::decode(
    const Ngap_UserLocationInformationEUTRA_t& userLocationInformation) {
  if (!m_EutraCgi.decode(userLocationInformation.eUTRA_CGI)) {
    oai::logger::logger_common::ngap().warn("Decode eUTRA_CGI IE error");
    return false;
  }

  if (!m_Tai.decode(userLocationInformation.tAI)) {
    oai::logger::logger_common::ngap().warn("Decode Tai IE error");
    return false;
  }
  return true;
}
}  // namespace oai::ngap
