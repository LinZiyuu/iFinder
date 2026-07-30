/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecurityIndication.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SecurityIndication::SecurityIndication() {
  m_MaximumIntegrityProtectedDataRateUl = std::nullopt;
  m_MaximumIntegrityProtectedDataRateDl = std::nullopt;
}

//------------------------------------------------------------------------------
SecurityIndication::SecurityIndication(
    const IntegrityProtectionIndication& integrityProtectionIndication,
    const ConfidentialityProtectionIndication&
        confidentialityProtectionIndication,
    const std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateUl,
    const std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateDl) {
  m_IntegrityProtectionIndication       = integrityProtectionIndication;
  m_ConfidentialityProtectionIndication = confidentialityProtectionIndication;
  m_MaximumIntegrityProtectedDataRateUl = maximumIntegrityProtectedDataRateUl;
  m_MaximumIntegrityProtectedDataRateDl = maximumIntegrityProtectedDataRateDl;
}

//------------------------------------------------------------------------------
SecurityIndication::~SecurityIndication() {}

//------------------------------------------------------------------------------
void SecurityIndication::set(
    const IntegrityProtectionIndication& integrityProtectionIndication,
    const ConfidentialityProtectionIndication&
        confidentialityProtectionIndication,
    const std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateUl,
    const std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateDl) {
  m_IntegrityProtectionIndication       = integrityProtectionIndication;
  m_ConfidentialityProtectionIndication = confidentialityProtectionIndication;
  m_MaximumIntegrityProtectedDataRateUl = maximumIntegrityProtectedDataRateUl;
  m_MaximumIntegrityProtectedDataRateDl = maximumIntegrityProtectedDataRateDl;
}

//------------------------------------------------------------------------------
void SecurityIndication::get(
    IntegrityProtectionIndication& integrityProtectionIndication,
    ConfidentialityProtectionIndication& confidentialityProtectionIndication,
    std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateUl,
    std::optional<MaximumIntegrityProtectedDataRate>&
        maximumIntegrityProtectedDataRateDl) const {
  integrityProtectionIndication       = m_IntegrityProtectionIndication;
  confidentialityProtectionIndication = m_ConfidentialityProtectionIndication;
  maximumIntegrityProtectedDataRateUl = m_MaximumIntegrityProtectedDataRateUl;
  maximumIntegrityProtectedDataRateDl = m_MaximumIntegrityProtectedDataRateDl;
}

//------------------------------------------------------------------------------
bool SecurityIndication::encode(
    Ngap_SecurityIndication_t& securityIndication) const {
  if (!m_IntegrityProtectionIndication.encode(
          securityIndication.integrityProtectionIndication))
    return false;
  if (!m_ConfidentialityProtectionIndication.encode(
          securityIndication.confidentialityProtectionIndication))
    return false;
  if (m_MaximumIntegrityProtectedDataRateUl.has_value()) {
    Ngap_MaximumIntegrityProtectedDataRate_t* maxIPDataRate =
        (Ngap_MaximumIntegrityProtectedDataRate_t*) calloc(
            1, sizeof(Ngap_MaximumIntegrityProtectedDataRate_t));
    if (!maxIPDataRate) return false;
    if (!m_MaximumIntegrityProtectedDataRateUl.value().encode(*maxIPDataRate)) {
      oai::utils::utils::free_wrapper((void**) &maxIPDataRate);
      return false;
    }

    securityIndication.maximumIntegrityProtectedDataRate_UL = maxIPDataRate;
    // oai::utils::utils::free_wrapper((void**) &maxIPDataRate);
  }
  // TODO: check maximumIntegrityProtectedDataRateDl

  return true;
}

//------------------------------------------------------------------------------
bool SecurityIndication::decode(
    const Ngap_SecurityIndication_t& securityIndication) {
  if (!m_IntegrityProtectionIndication.decode(
          securityIndication.integrityProtectionIndication))
    return false;
  if (!m_ConfidentialityProtectionIndication.decode(
          securityIndication.confidentialityProtectionIndication))
    return false;

  // TODO: verify maximumIntegrityProtectedDataRate
  if (securityIndication.maximumIntegrityProtectedDataRate_UL) {
    MaximumIntegrityProtectedDataRate tmp = {};

    if (!tmp.decode(*securityIndication.maximumIntegrityProtectedDataRate_UL))
      return false;
    m_MaximumIntegrityProtectedDataRateUl =
        std::make_optional<MaximumIntegrityProtectedDataRate>(tmp);
  }
  // TODO: verify maximumIntegrityProtectedDataRateDl

  return true;
}

}  // namespace oai::ngap
