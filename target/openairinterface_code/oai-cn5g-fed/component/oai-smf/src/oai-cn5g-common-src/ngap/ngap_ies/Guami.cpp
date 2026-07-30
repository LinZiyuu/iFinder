/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Guami.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
Guami::Guami() {}

//------------------------------------------------------------------------------
Guami::~Guami() {}

//------------------------------------------------------------------------------
void Guami::set(
    const PlmnId& plmnId, const AmfRegionId& amfRegionId,
    const AmfSetId& amfSetId, const AmfPointer& amfPointer) {
  m_PlmnId      = plmnId;
  m_AmfRegionId = amfRegionId;
  m_AmfSetId    = amfSetId;
  m_AmfPointer  = amfPointer;
}

//------------------------------------------------------------------------------
bool Guami::set(
    const std::string& mcc, const std::string& mnc, uint8_t regionId,
    uint16_t setId, uint8_t pointer) {
  m_PlmnId.set(mcc, mnc);
  m_AmfRegionId.set(regionId);
  if (!m_AmfSetId.set(setId)) return false;
  if (!m_AmfPointer.set(pointer)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool Guami::set(
    const std::string& mcc, const std::string& mnc, const std::string& regionId,
    const std::string& setId, const std::string& pointer) {
  m_PlmnId.set(mcc, mnc);
  m_AmfRegionId.set(regionId);
  if (!m_AmfSetId.set(setId)) return false;
  if (!m_AmfPointer.set(pointer)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool Guami::encode(Ngap_GUAMI_t& guami) const {
  if (!m_PlmnId.encode(guami.pLMNIdentity)) return false;
  if (!m_AmfRegionId.encode(guami.aMFRegionID)) return false;
  if (!m_AmfSetId.encode(guami.aMFSetID)) return false;
  if (!m_AmfPointer.encode(guami.aMFPointer)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool Guami::decode(const Ngap_GUAMI_t& pdu) {
  if (!m_PlmnId.decode(pdu.pLMNIdentity)) return false;
  if (!m_AmfRegionId.decode(pdu.aMFRegionID)) return false;
  if (!m_AmfSetId.decode(pdu.aMFSetID)) return false;
  if (!m_AmfPointer.decode(pdu.aMFPointer)) return false;

  return true;
}

//------------------------------------------------------------------------------
void Guami::get(
    PlmnId& plmnId, AmfRegionId& amfRegionId, AmfSetId& amfSetId,
    AmfPointer& amfPointer) const {
  plmnId      = m_PlmnId;
  amfRegionId = m_AmfRegionId;
  amfSetId    = m_AmfSetId;
  amfPointer  = m_AmfPointer;
}

//------------------------------------------------------------------------------
void Guami::get(
    std::string& mcc, std::string& mnc, std::string& regionId,
    std::string& setId, std::string& pointer) const {
  m_PlmnId.getMcc(mcc);
  m_PlmnId.getMnc(mnc);
  m_AmfRegionId.get(regionId);
  m_AmfSetId.get(setId);
  m_AmfPointer.get(pointer);
}

//------------------------------------------------------------------------------
void Guami::get(
    std::string& mcc, std::string& mnc, uint8_t& regionId, uint16_t& setId,
    uint8_t& pointer) const {
  m_PlmnId.getMcc(mcc);
  m_PlmnId.getMnc(mnc);
  m_AmfRegionId.get(regionId);
  m_AmfSetId.get(setId);
  m_AmfPointer.get(pointer);
}

}  // namespace oai::ngap
