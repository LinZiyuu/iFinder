/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UserLocationInformationNr.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UserLocationInformationNr::UserLocationInformationNr() {}

//------------------------------------------------------------------------------
UserLocationInformationNr::~UserLocationInformationNr() {}

//------------------------------------------------------------------------------
void UserLocationInformationNr::set(const NrCgi& nrCgi, const Tai& tai) {
  m_NrCgi = nrCgi;
  m_Tai   = tai;
}

//------------------------------------------------------------------------------
bool UserLocationInformationNr::encode(
    Ngap_UserLocationInformationNR_t& userLocationInformation) const {
  if (!m_NrCgi.encode(userLocationInformation.nR_CGI)) {
    return false;
  }
  if (!m_Tai.encode(userLocationInformation.tAI)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UserLocationInformationNr::decode(
    const Ngap_UserLocationInformationNR_t& userLocationInformation) {
  if (!m_NrCgi.decode(userLocationInformation.nR_CGI)) {
    return false;
  }

  if (!m_Tai.decode(userLocationInformation.tAI)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void UserLocationInformationNr::get(NrCgi& nrCgi, Tai& tai) const {
  nrCgi = m_NrCgi;
  tai   = m_Tai;
}
}  // namespace oai::ngap
