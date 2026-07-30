/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MicoModeIndication.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
MicoModeIndication::MicoModeIndication()
    : m_MicoModeIndication(Ngap_MICOModeIndication_true) {}

//------------------------------------------------------------------------------
MicoModeIndication::~MicoModeIndication() {}

//------------------------------------------------------------------------------
void MicoModeIndication::set(const long& micoModeIndication) {
  m_MicoModeIndication = micoModeIndication;
}

//------------------------------------------------------------------------------
void MicoModeIndication::get(long& micoModeIndication) const {
  micoModeIndication = m_MicoModeIndication;
}

//------------------------------------------------------------------------------
bool MicoModeIndication::encode(
    Ngap_MICOModeIndication_t& micoModeIndication) const {
  if (!micoModeIndication) return false;
  micoModeIndication = m_MicoModeIndication;

  return true;
}

//------------------------------------------------------------------------------
bool MicoModeIndication::decode(
    const Ngap_MICOModeIndication_t& micoModeIndication) {
  if (!micoModeIndication) return false;
  m_MicoModeIndication = micoModeIndication;

  return true;
}

}  // namespace oai::ngap
