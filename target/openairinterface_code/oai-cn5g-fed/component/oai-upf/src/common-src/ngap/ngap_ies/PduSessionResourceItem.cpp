/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceItem.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceItem::PduSessionResourceItem() {}

//------------------------------------------------------------------------------
PduSessionResourceItem::~PduSessionResourceItem() {}

//------------------------------------------------------------------------------
void PduSessionResourceItem::set(
    const PduSessionId& pduSessionId, const OCTET_STRING_t& resource) {
  m_PduSessionId = pduSessionId;
  // m_Resource = resource;
  ngap_utils::octet_string_copy(m_Resource, resource);
}

//------------------------------------------------------------------------------
void PduSessionResourceItem::get(
    PduSessionId& pduSessionId, OCTET_STRING_t& resource) const {
  pduSessionId = m_PduSessionId;
  // resource = m_Resource;
  ngap_utils::octet_string_copy(resource, m_Resource);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionID_t& pduSessionId, OCTET_STRING_t& resource) const {
  if (!m_PduSessionId.encode(pduSessionId)) return false;
  return ngap_utils::octet_string_copy(resource, m_Resource);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionID_t& pduSessionId, const OCTET_STRING_t& resource) {
  if (!m_PduSessionId.decode(pduSessionId)) return false;
  return ngap_utils::octet_string_copy(m_Resource, resource);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceSetupItemCxtRes_t& item) const {
  return encode(
      item.pDUSessionID, item.pDUSessionResourceSetupResponseTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceSetupItemCxtRes_t& item) {
  return decode(
      item.pDUSessionID, item.pDUSessionResourceSetupResponseTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceItemHORqd_t& item) const {
  return encode(item.pDUSessionID, item.handoverRequiredTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceItemHORqd_t& item) {
  return decode(item.pDUSessionID, item.handoverRequiredTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceHandoverItem_t& item) const {
  return encode(item.pDUSessionID, item.handoverCommandTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceHandoverItem_t& item) {
  return decode(item.pDUSessionID, item.handoverCommandTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceToReleaseItemHOCmd_t& item) const {
  return encode(
      item.pDUSessionID, item.handoverPreparationUnsuccessfulTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceToReleaseItemHOCmd_t& item) {
  return decode(
      item.pDUSessionID, item.handoverPreparationUnsuccessfulTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceAdmittedItem_t& item) const {
  return encode(item.pDUSessionID, item.handoverRequestAcknowledgeTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceAdmittedItem_t& item) {
  return decode(item.pDUSessionID, item.handoverRequestAcknowledgeTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::encode(
    Ngap_PDUSessionResourceFailedToSetupItemHOAck_t& item) const {
  return encode(
      item.pDUSessionID, item.handoverResourceAllocationUnsuccessfulTransfer);
}

//------------------------------------------------------------------------------
bool PduSessionResourceItem::decode(
    const Ngap_PDUSessionResourceFailedToSetupItemHOAck_t& item) {
  return decode(
      item.pDUSessionID, item.handoverResourceAllocationUnsuccessfulTransfer);
}

}  // namespace oai::ngap
