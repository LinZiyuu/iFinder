/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyUnsuccessfulTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyUnSuccessfulTransfer::
    PduSessionResourceModifyUnSuccessfulTransfer() {
  m_PduSessionResourceModifyUnsuccessfulTransferIe =
      (Ngap_PDUSessionResourceModifyUnsuccessfulTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceModifyUnsuccessfulTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceModifyUnSuccessfulTransfer::
    ~PduSessionResourceModifyUnSuccessfulTransfer() {}

//------------------------------------------------------------------------------
void PduSessionResourceModifyUnSuccessfulTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceModifyUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyUnSuccessfulTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceModifyUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyUnSuccessfulTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceModifyUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyUnSuccessfulTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceModifyUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyUnSuccessfulTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_Cause.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_Cause.set(causeValue);

  int ret =
      m_Cause.encode(m_PduSessionResourceModifyUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
int PduSessionResourceModifyUnSuccessfulTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceModifyUnsuccessfulTransfer,
      m_PduSessionResourceModifyUnsuccessfulTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceModifyUnsuccessfulTransfer, NULL,
      m_PduSessionResourceModifyUnsuccessfulTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
// Decapsulation
bool PduSessionResourceModifyUnSuccessfulTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyUnsuccessfulTransfer,
      (void**) &m_PduSessionResourceModifyUnsuccessfulTransferIe, buf, bufSize);

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
  // &asn_DEF_Ngap_PDUSessionResourceModifyUnsuccessfulTransfer,
  // m_PduSessionResourceModifyUnsuccessfulTransferIe);

  if (!m_Cause.decode(
          m_PduSessionResourceModifyUnsuccessfulTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
long PduSessionResourceModifyUnSuccessfulTransfer::getChoiceOfCause() const {
  return m_Cause.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long PduSessionResourceModifyUnSuccessfulTransfer::getCause() const {
  return m_Cause.get();
}
}  // namespace oai::ngap
