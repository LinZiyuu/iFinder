/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupUnsuccessfulTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupUnsuccessfulTransfer::
    PduSessionResourceSetupUnsuccessfulTransfer() {
  m_PduSessionResourceSetupUnsuccessfulTransferIe =
      (Ngap_PDUSessionResourceSetupUnsuccessfulTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceSetupUnsuccessfulTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceSetupUnsuccessfulTransfer::
    ~PduSessionResourceSetupUnsuccessfulTransfer() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupUnsuccessfulTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupUnsuccessfulTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupUnsuccessfulTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupUnsuccessfulTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupUnsuccessfulTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
int PduSessionResourceSetupUnsuccessfulTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceSetupUnsuccessfulTransfer,
      m_PduSessionResourceSetupUnsuccessfulTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceSetupUnsuccessfulTransfer, NULL,
      m_PduSessionResourceSetupUnsuccessfulTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
// Decapsulation
bool PduSessionResourceSetupUnsuccessfulTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceSetupUnsuccessfulTransfer,
      (void**) &m_PduSessionResourceSetupUnsuccessfulTransferIe, buf, bufSize);

  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug("Failure to decode data");
    return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode %d", rc.consumed);

  // asn_fprint(stderr,
  // &asn_DEF_Ngap_PDUSessionResourceSetupUnsuccessfulTransfer,
  // m_PduSessionResourceSetupUnsuccessfulTransferIe);

  if (!m_Cause.decode(m_PduSessionResourceSetupUnsuccessfulTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
long PduSessionResourceSetupUnsuccessfulTransfer::getChoiceOfCause() const {
  return m_Cause.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long PduSessionResourceSetupUnsuccessfulTransfer::getCause() const {
  return m_Cause.get();
}
}  // namespace oai::ngap
