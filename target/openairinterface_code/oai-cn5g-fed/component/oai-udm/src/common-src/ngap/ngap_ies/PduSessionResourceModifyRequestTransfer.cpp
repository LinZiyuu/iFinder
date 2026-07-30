/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyRequestTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyRequestTransfer::
    PduSessionResourceModifyRequestTransfer() {
  m_Ie = (Ngap_PDUSessionResourceModifyRequestTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceModifyRequestTransfer_t));
  m_PduSessionAggregateMaximumBitRateIe = std::nullopt;
  m_NetworkInstance                     = std::nullopt;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::
    setPduSessionAggregateMaximumBitRate(
        const long& bitRateDl, const long& bitRateUl) {
  m_PduSessionAggregateMaximumBitRateIe =
      std::make_optional<PduSessionAggregateMaximumBitRate>(
          bitRateDl, bitRateUl);

  // Add to the PduSessionResourceModifyRequestTransfer->protocolIEs.list
  addPduSessionAggregateMaximumBitRate();
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::
    setPduSessionAggregateMaximumBitRate(
        const PduSessionAggregateMaximumBitRate& maxBitRate) {
  m_PduSessionAggregateMaximumBitRateIe =
      std::make_optional<PduSessionAggregateMaximumBitRate>(maxBitRate);

  // Add to the PduSessionResourceModifyRequestTransfer->protocolIEs.list
  addPduSessionAggregateMaximumBitRate();
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::
    getPduSessionAggregateMaximumBitRate(
        std::optional<PduSessionAggregateMaximumBitRate>& maxBitRate) const {
  maxBitRate = m_PduSessionAggregateMaximumBitRateIe;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::
    addPduSessionAggregateMaximumBitRate() {
  if (!m_PduSessionAggregateMaximumBitRateIe.has_value()) return;

  Ngap_PDUSessionResourceModifyRequestTransferIEs_t* ie =
      (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;

  int ret = m_PduSessionAggregateMaximumBitRateIe.value().encode(
      ie->value.choice.PDUSessionAggregateMaximumBitRate);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionAggregateMaximumBitRate IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_Ie->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode PDUSessionAggregateMaximumBitRate IE error");
  // oai::utils::utils::free_wrapper((void**) &ie);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::setUlNgUUpTnlModifyList(
    const UlNgUUpTnlModifyList& ulNgUUpTnlModifyList) {
  m_UlNgUUpTnlModifyList =
      std::make_optional<UlNgUUpTnlModifyList>(ulNgUUpTnlModifyList);

  Ngap_PDUSessionResourceModifyRequestTransferIEs_t* ie =
      (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLModifyList;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_UL_NGU_UP_TNLModifyList;

  int ret = m_UlNgUUpTnlModifyList.value().encode(
      ie->value.choice.UL_NGU_UP_TNLModifyList);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode UL_NGU_UP_TNLModifyList IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_Ie->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode UL_NGU_UP_TNLModifyList IE error");
  // oai::utils::utils::free_wrapper((void**) &ie);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::getUlNgUUpTnlModifyList(
    std::optional<UlNgUUpTnlModifyList>& ulNgUUpTnlModifyList) const {
  ulNgUUpTnlModifyList = m_UlNgUUpTnlModifyList;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::setNetworkInstance(
    const long& value) {
  m_NetworkInstance = std::make_optional<NetworkInstance>(value);

  Ngap_PDUSessionResourceModifyRequestTransferIEs_t* ie =
      (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_NetworkInstance;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_NetworkInstance;

  int ret = m_NetworkInstance.value().encode(ie->value.choice.NetworkInstance);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode NetworkInstance IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_Ie->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode NetworkInstance IE error");
  // oai::utils::utils::free_wrapper((void**) &ie);
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyRequestTransfer::getNetworkInstance(
    long& value) const {
  if (!m_NetworkInstance.has_value()) return false;

  if (!m_NetworkInstance.value().get(value)) return false;

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::getNetworkInstance(
    std::optional<NetworkInstance>& networkInstance) const {
  networkInstance = m_NetworkInstance;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::setQosFlowAddOrModifyRequestList(
    const std::vector<QosFlowAddOrModifyRequestItem> list) {
  QosFlowAddOrModifyRequestList qosFlowAddOrModifyRequestList;
  qosFlowAddOrModifyRequestList.set(list);
  m_QosFlowAddOrModifyRequestList =
      std::make_optional<QosFlowAddOrModifyRequestList>(
          qosFlowAddOrModifyRequestList);

  // Add to the PduSessionResourceModifyRequestTransfer->protocolIEs.list
  addQosFlowAddOrModifyRequestList();
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::setQosFlowAddOrModifyRequestList(
    const QosFlowAddOrModifyRequestList& list) {
  m_QosFlowAddOrModifyRequestList =
      std::make_optional<QosFlowAddOrModifyRequestList>(list);

  // Add to the PduSessionResourceModifyRequestTransfer->protocolIEs.list
  addQosFlowAddOrModifyRequestList();
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::getQosFlowAddOrModifyRequestList(
    std::optional<QosFlowAddOrModifyRequestList>& list) const {
  list = m_QosFlowAddOrModifyRequestList;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyRequestTransfer::
    addQosFlowAddOrModifyRequestList() {
  Ngap_PDUSessionResourceModifyRequestTransferIEs_t* ie =
      (Ngap_PDUSessionResourceModifyRequestTransferIEs_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyRequestTransferIEs_t));
  ie->id          = Ngap_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowAddOrModifyRequestList;

  int ret = m_QosFlowAddOrModifyRequestList.value().encode(
      ie->value.choice.QosFlowAddOrModifyRequestList);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode QosFlowAddOrModifyRequestList IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_Ie->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error(
        "Encode QosFlowAddOrModifyRequestList IE error");
  // oai::utils::utils::free_wrapper((void**) &ie);
}

//------------------------------------------------------------------------------
int PduSessionResourceModifyRequestTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceModifyRequestTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceModifyRequestTransfer, NULL, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyRequestTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyRequestTransfer, (void**) &m_Ie,
      buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug("Failure to decode data");
    return false;
  }

  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceSetupRequestTransfer,
  // m_Ie);

  for (int i = 0; i < m_Ie->protocolIEs.list.count; i++) {
    switch (m_Ie->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate: {
        if (m_Ie->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_Ie->protocolIEs.list.array[i]->value.present ==
                Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate) {
          PduSessionAggregateMaximumBitRate aggregateMaximumBitRate = {};

          if (!aggregateMaximumBitRate.decode(
                  m_Ie->protocolIEs.list.array[i]
                      ->value.choice.PDUSessionAggregateMaximumBitRate)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP PDUSessionAggregateMaximumBitRate IE error");
            return false;
          }
          m_PduSessionAggregateMaximumBitRateIe =
              std::make_optional<PduSessionAggregateMaximumBitRate>(
                  aggregateMaximumBitRate);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP PDUSessionAggregateMaximumBitRate IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_UL_NGU_UP_TNLModifyList: {
        if (m_Ie->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_Ie->protocolIEs.list.array[i]->value.present ==
                Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_UL_NGU_UP_TNLModifyList) {
          UlNgUUpTnlModifyList ulNgUUpTnlModifyList = {};
          if (!ulNgUUpTnlModifyList.decode(
                  m_Ie->protocolIEs.list.array[i]
                      ->value.choice.UL_NGU_UP_TNLModifyList)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP UPTransportLayerInformation IE error");
            return false;
          }
          m_UlNgUUpTnlModifyList =
              std::make_optional<UlNgUUpTnlModifyList>(ulNgUUpTnlModifyList);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP UPTransportLayerInformation IE error");
          return false;
        }
      } break;

      case Ngap_ProtocolIE_ID_id_NetworkInstance: {
        if (m_Ie->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_Ie->protocolIEs.list.array[i]->value.present ==
                Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_NetworkInstance) {
          NetworkInstance networkInstance = {};
          if (!networkInstance.decode(m_Ie->protocolIEs.list.array[i]
                                          ->value.choice.NetworkInstance)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP NetworkInstance IE error");
            return false;
          }
          m_NetworkInstance =
              std::make_optional<NetworkInstance>(networkInstance);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP NetworkInstance IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList: {
        if (m_Ie->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_reject &&
            m_Ie->protocolIEs.list.array[i]->value.present ==
                Ngap_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowAddOrModifyRequestList) {
          QosFlowAddOrModifyRequestList qosFlowAddOrModifyRequestList = {};
          if (!qosFlowAddOrModifyRequestList.decode(
                  m_Ie->protocolIEs.list.array[i]
                      ->value.choice.QosFlowAddOrModifyRequestList)) {
            oai::logger::logger_common::ngap().error(
                "Decode NGAP QosFlowSetupRequestList IE error");
            return false;
          }
          m_QosFlowAddOrModifyRequestList =
              std::make_optional<QosFlowAddOrModifyRequestList>(
                  qosFlowAddOrModifyRequestList);

        } else {
          oai::logger::logger_common::ngap().error(
              "Decode NGAP QosFlowSetupRequestList IE error");
          return false;
        }
      } break;
      // TODO: QoS Flow to Release List (Optional)
      // TODO: Additional UL NG-U UP TNL Information (Optional)
      // TODO: Common Network Instance (Optional)
      // TODO: Additional Redundant UL NG-U UP TNL Information (Optional)
      // TODO: Redundant Common Network Instance (Optional)
      // TODO: Redundant UL NG-U UP TNL Information (Optional)
      // TODO: Security Indication (Optional)
      default: {
        oai::logger::logger_common::ngap().error(
            "Decode NGAP message PduSessionResourceModifyRequestTransfer "
            "error");
        return false;
      }
    }
  }

  return true;
}

}  // namespace oai::ngap
