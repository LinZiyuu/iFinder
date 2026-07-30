/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NgSetupFailure.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NgSetupFailureMsg::NgSetupFailureMsg() : NgapMessage() {
  m_NgSetupFailureIes = nullptr;
  // criticalityDiagnostics = NULL;
  m_TimeToWait = std::nullopt;
  NgapMessage::setMessageType(NgapMessageType::NG_SETUP_FAILURE);
  initialize();
}

//------------------------------------------------------------------------------
NgSetupFailureMsg::~NgSetupFailureMsg() {}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::initialize() {
  m_NgSetupFailureIes =
      &(ngapPdu->choice.unsuccessfulOutcome->value.choice.NGSetupFailure);
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::addCauseIe() {
  Ngap_NGSetupFailureIEs_t* ie =
      (Ngap_NGSetupFailureIEs_t*) calloc(1, sizeof(Ngap_NGSetupFailureIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_Cause;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_NGSetupFailureIEs__value_PR_Cause;

  if (!m_Cause.encode(ie->value.choice.Cause)) {
    oai::logger::logger_common::ngap().error("Encode NGAP Cause IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  int ret = ASN_SEQUENCE_ADD(&m_NgSetupFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode NGAP Cause IE error");
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::addTimeToWaitIE() {
  if (!m_TimeToWait.has_value()) return;

  Ngap_NGSetupFailureIEs_t* ie =
      (Ngap_NGSetupFailureIEs_t*) calloc(1, sizeof(Ngap_NGSetupFailureIEs_t));
  ie->id            = Ngap_ProtocolIE_ID_id_TimeToWait;
  ie->criticality   = Ngap_Criticality_ignore;
  ie->value.present = Ngap_NGSetupFailureIEs__value_PR_TimeToWait;

  if (!m_TimeToWait.value().encode(ie->value.choice.TimeToWait)) {
    oai::logger::logger_common::ngap().error("Encode NGAP Cause IE error");
    oai::utils::utils::free_wrapper((void**) &ie);
    return;
  }

  int ret = ASN_SEQUENCE_ADD(&m_NgSetupFailureIes->protocolIEs.list, ie);
  if (ret != 0)
    oai::logger::logger_common::ngap().error("Encode NGAP TimeToWait IE error");
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::set(
    const e_Ngap_CauseRadioNetwork& causeValue,
    const e_Ngap_TimeToWait& timeToWait) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_Cause.set(causeValue);
  addCauseIe();

  m_TimeToWait = std::make_optional<TimeToWait>(timeToWait);
  addTimeToWaitIE();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setCauseRadioNetwork(
    const e_Ngap_CauseRadioNetwork& causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_Cause.set(causeValue);
  addCauseIe();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::set(
    const e_Ngap_CauseTransport& causeValue,
    const e_Ngap_TimeToWait& timeToWait) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_Cause.set(causeValue);
  addCauseIe();

  m_TimeToWait = std::make_optional<TimeToWait>(timeToWait);
  addTimeToWaitIE();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setCauseTransport(
    const e_Ngap_CauseTransport& causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_Cause.set(causeValue);
  addCauseIe();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::set(
    const e_Ngap_CauseNas& causeValue, const e_Ngap_TimeToWait& timeToWait) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_Cause.set(causeValue);
  addCauseIe();

  m_TimeToWait = std::make_optional<TimeToWait>(timeToWait);
  addTimeToWaitIE();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setCauseNas(const e_Ngap_CauseNas& causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_Cause.set(causeValue);
  addCauseIe();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::set(
    const e_Ngap_CauseProtocol& causeValue,
    const e_Ngap_TimeToWait& timeToWait) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_Cause.set(causeValue);
  addCauseIe();

  m_TimeToWait = std::make_optional<TimeToWait>(timeToWait);
  addTimeToWaitIE();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setCauseProtocol(
    const e_Ngap_CauseProtocol& causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_Cause.set(causeValue);
  addCauseIe();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::set(
    const e_Ngap_CauseMisc& causeValue, const e_Ngap_TimeToWait& timeToWait) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_Cause.set(causeValue);
  addCauseIe();

  m_TimeToWait = std::make_optional<TimeToWait>(timeToWait);
  addTimeToWaitIE();
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setCauseMisc(const e_Ngap_CauseMisc& causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_Cause.set(causeValue);
  addCauseIe();
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::decode(Ngap_NGAP_PDU_t* ngapMsgPdu) {
  ngapPdu = ngapMsgPdu;
  if (ngapPdu->present == Ngap_NGAP_PDU_PR_unsuccessfulOutcome) {
    if (ngapPdu->choice.unsuccessfulOutcome &&
        ngapPdu->choice.unsuccessfulOutcome->procedureCode ==
            Ngap_ProcedureCode_id_NGSetup &&
        ngapPdu->choice.unsuccessfulOutcome->criticality ==
            Ngap_Criticality_reject &&
        ngapPdu->choice.unsuccessfulOutcome->value.present ==
            Ngap_UnsuccessfulOutcome__value_PR_NGSetupFailure) {
      m_NgSetupFailureIes =
          &ngapPdu->choice.unsuccessfulOutcome->value.choice.NGSetupFailure;
    } else {
      oai::logger::logger_common::ngap().error(
          "Check NGSetupFailure message error!");
      return false;
    }
  } else {
    oai::logger::logger_common::ngap().error("MessageType error!");
    return false;
  }
  for (int i = 0; i < m_NgSetupFailureIes->protocolIEs.list.count; i++) {
    switch (m_NgSetupFailureIes->protocolIEs.list.array[i]->id) {
      case Ngap_ProtocolIE_ID_id_Cause: {
        if (m_NgSetupFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_NgSetupFailureIes->protocolIEs.list.array[i]->value.present ==
                Ngap_NGSetupFailureIEs__value_PR_Cause) {
          if (!m_Cause.decode(m_NgSetupFailureIes->protocolIEs.list.array[i]
                                  ->value.choice.Cause)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP Cause IE error");
            return false;
          }
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP Cause IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_TimeToWait: {
        if (m_NgSetupFailureIes->protocolIEs.list.array[i]->criticality ==
                Ngap_Criticality_ignore &&
            m_NgSetupFailureIes->protocolIEs.list.array[i]->value.present ==
                Ngap_NGSetupFailureIEs__value_PR_TimeToWait) {
          TimeToWait tmp = {};
          if (!tmp.decode(m_NgSetupFailureIes->protocolIEs.list.array[i]
                              ->value.choice.TimeToWait)) {
            oai::logger::logger_common::ngap().error(
                "Decoded NGAP TimeToWait IE error");
            return false;
          }
          m_TimeToWait = std::optional<TimeToWait>(tmp);
        } else {
          oai::logger::logger_common::ngap().error(
              "Decoded NGAP TimeToWait IE error");
          return false;
        }
      } break;
      case Ngap_ProtocolIE_ID_id_CriticalityDiagnostics: {
        oai::logger::logger_common::ngap().debug(
            "Decoded NGAP CriticalityDiagnostics IE ");
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

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseType(Ngap_Cause_PR& causePresent) const {
  if (m_Cause.getChoiceOfCause() < 0) {
    return false;
  }
  causePresent = m_Cause.getChoiceOfCause();
  return true;
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork& causeRadioNetwork) const {
  if (m_Cause.get() < 0) {
    return false;
  }
  causeRadioNetwork = (e_Ngap_CauseRadioNetwork) m_Cause.get();
  return true;
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseTransport(
    e_Ngap_CauseTransport& causeTransport) const {
  if (m_Cause.get() < 0) {
    return false;
  }
  causeTransport = (e_Ngap_CauseTransport) m_Cause.get();
  return true;
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseNas(e_Ngap_CauseNas& causeNas) const {
  if (m_Cause.get() < 0) {
    return false;
  }
  causeNas = (e_Ngap_CauseNas) m_Cause.get();
  return true;
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseProtocol(
    e_Ngap_CauseProtocol& causeProtocol) const {
  if (m_Cause.get() < 0) {
    return false;
  }
  causeProtocol = (e_Ngap_CauseProtocol) m_Cause.get();
  return true;
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getCauseMisc(e_Ngap_CauseMisc& causeMisc) const {
  if (m_Cause.get() < 0) {
    return false;
  }
  causeMisc = (e_Ngap_CauseMisc) m_Cause.get();
  return true;
}

//------------------------------------------------------------------------------
void NgSetupFailureMsg::setTimeToWait(const e_Ngap_TimeToWait& time) {
  m_TimeToWait = std::make_optional<TimeToWait>(time);
}

//------------------------------------------------------------------------------
bool NgSetupFailureMsg::getTimeToWait(e_Ngap_TimeToWait& time) const {
  if (m_TimeToWait.has_value()) {
    return false;
  }
  time = (e_Ngap_TimeToWait) m_TimeToWait.value().get();
  return true;
}

}  // namespace oai::ngap
