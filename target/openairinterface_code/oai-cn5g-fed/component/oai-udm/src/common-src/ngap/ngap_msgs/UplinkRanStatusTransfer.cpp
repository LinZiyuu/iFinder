/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UplinkRanStatusTransfer.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UplinkRanStatusTransfer::UplinkRanStatusTransfer() : NgapUeMessage() {
  m_UplinkRanStatusTransferIes = nullptr;

  setMessageType(NgapMessageType::UPLINK_RAN_STATUS_TRANSFER);
  initialize();
}

//------------------------------------------------------------------------------
UplinkRanStatusTransfer::~UplinkRanStatusTransfer() {}

//------------------------------------------------------------------------------
void UplinkRanStatusTransfer::initialize() {
  m_UplinkRanStatusTransferIes =
      &ngapPdu->choice.initiatingMessage->value.choice.UplinkRANStatusTransfer;
}

//------------------------------------------------------------------------------
void UplinkRanStatusTransfer::setAmfUeNgapId(const uint64_t& id) {
  NgapUeMessage::m_AmfUeNgapId.set(id);

  Ngap_UplinkRANStatusTransferIEs_t* ie =
      (Ngap_UplinkRANStatusTransferIEs_t*) calloc(
          1, sizeof(Ngap_UplinkRANStatusTransferIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_UplinkRANStatusTransferIEs__value_PR_AMF_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_AmfUeNgapId.encode(ie->value.choice.AMF_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_UplinkRanStatusTransferIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode AMF_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
void UplinkRanStatusTransfer::setRanUeNgapId(const uint32_t& ranUeNgapId) {
  NgapUeMessage::m_RanUeNgapId.set(ranUeNgapId);

  Ngap_UplinkRANStatusTransferIEs_t* ie =
      (Ngap_UplinkRANStatusTransferIEs_t*) calloc(
          1, sizeof(Ngap_UplinkRANStatusTransferIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
  ie->criticality   = Ngap_Criticality_reject;
  ie->value.present = Ngap_UplinkRANStatusTransferIEs__value_PR_RAN_UE_NGAP_ID;

  int ret =
      NgapUeMessage::m_RanUeNgapId.encode(ie->value.choice.RAN_UE_NGAP_ID);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_UplinkRanStatusTransferIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
void UplinkRanStatusTransfer::setRanStatusTransferTransparentContainer(
    const RanStatusTransferTransparentContainer& ranContainer) {
  m_RanStatusTransferTransparentContainer = ranContainer;

  Ngap_UplinkRANStatusTransferIEs_t* ie =
      (Ngap_UplinkRANStatusTransferIEs_t*) calloc(
          1, sizeof(Ngap_UplinkRANStatusTransferIEs_t));
  ie->id = Ngap_ProtocolIE_ID_id_RANStatusTransfer_TransparentContainer;
  ie->criticality = Ngap_Criticality_reject;
  ie->value.present =
      Ngap_UplinkRANStatusTransferIEs__value_PR_RANStatusTransfer_TransparentContainer;

  int ret = m_RanStatusTransferTransparentContainer.encode(
      ie->value.choice.RANStatusTransfer_TransparentContainer);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode RANStatusTransfer_TransparentContainer IE error!");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  ret = ASN_SEQUENCE_ADD(&m_UplinkRanStatusTransferIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode RAN_UE_NGAP_ID IE error!");
}

//------------------------------------------------------------------------------
void UplinkRanStatusTransfer::getRanStatusTransferTransparentContainer(
    RanStatusTransferTransparentContainer& ranContainer) const {
  ranContainer = m_RanStatusTransferTransparentContainer;
}

//------------------------------------------------------------------------------
bool UplinkRanStatusTransfer::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;
  if (ngapPdu->present == Ngap_NGAP_PDU_PR_initiatingMessage) {
    if (ngapPdu->choice.initiatingMessage &&
        ngapPdu->choice.initiatingMessage->procedureCode ==
            Ngap_ProcedureCode_id_UplinkRANStatusTransfer &&
        ngapPdu->choice.initiatingMessage->criticality ==
            Ngap_Criticality_ignore &&
        ngapPdu->choice.initiatingMessage->value.present ==
            Ngap_InitiatingMessage__value_PR_UplinkRANStatusTransfer) {
      m_UplinkRanStatusTransferIes = &ngapPdu->choice.initiatingMessage->value
                                          .choice.UplinkRANStatusTransfer;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check UplinkRANStatusTransfer message error");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error(
        "UplinkRANStatusTransfer message type error");
    return false;
  }
  for (int i = 0; i < m_UplinkRanStatusTransferIes->protocolIEs.list.count;
       i++) {
    switch (m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID: {
        if (m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkRANStatusTransferIEs__value_PR_AMF_UE_NGAP_ID) {
          if (!NgapUeMessage::m_AmfUeNgapId.decode(
                  m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                      ->value.choice.AMF_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP AMF_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP AMF_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID: {
        if (m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkRANStatusTransferIEs__value_PR_RAN_UE_NGAP_ID) {
          if (!NgapUeMessage::m_RanUeNgapId.decode(
                  m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                      ->value.choice.RAN_UE_NGAP_ID)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP RAN_UE_NGAP_ID IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP RAN_UE_NGAP_ID IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_RANStatusTransfer_TransparentContainer: {
        if (m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->criticality == Ngap_Criticality_reject &&
            m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                    ->value.present ==
                Ngap_UplinkRANStatusTransferIEs__value_PR_RANStatusTransfer_TransparentContainer) {
          if (!m_RanStatusTransferTransparentContainer.decode(
                  m_UplinkRanStatusTransferIes->protocolIEs.list.array[i]
                      ->value.choice.RANStatusTransfer_TransparentContainer)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP RANStatusTransfer_TransparentContainer IE "
                "error");
            return false;
          }
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP RANStatusTransfer_TransparentContainer IE "
              "error");
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP RANStatusTransfer_TransparentContainer IE "
              "error");
        }
      } break;
      default: {
        oai::logger::logger_common::ngap().error(
            "Decoded NGAP message PDU error");
        return false;
      }
    }
  }
  return true;
}

}  // namespace oai::ngap
