/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleaseCommandTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleaseCommandTransfer::
    PduSessionResourceReleaseCommandTransfer() {
  m_PduSessionResourceReleaseCommandTransferIe =
      (Ngap_PDUSessionResourceReleaseCommandTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseCommandTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceReleaseCommandTransfer::
    ~PduSessionResourceReleaseCommandTransfer() {
  // if(m_PduSessionResourceReleaseCommandTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,m_PduSessionResourceReleaseCommandTransferIe);
  // if (m_PduSessionResourceReleaseCommandTransferIe)
  // free(m_PduSessionResourceReleaseCommandTransferIe);
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCause(const Cause& cause) {
  m_CauseValue = cause;
  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode Cause IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceReleaseCommandTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
int PduSessionResourceReleaseCommandTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,
      m_PduSessionResourceReleaseCommandTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer, NULL,
      m_PduSessionResourceReleaseCommandTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseCommandTransfer::encode2NewBuffer(
    uint8_t*& buf, int& encoded_size) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,
      m_PduSessionResourceReleaseCommandTransferIe);
  encoded_size = aper_encode_to_new_buffer(
      &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer, NULL,
      m_PduSessionResourceReleaseCommandTransferIe, (void**) &buf);
  oai::logger::logger_common::ngap().debug(
      "Encoded message size ( %d )", encoded_size);
  return;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseCommandTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,
      (void**) &m_PduSessionResourceReleaseCommandTransferIe, buf, bufSize);

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
  // pduSessionResourceSetupUnsuccessfulTransferIEs);

  if (!m_CauseValue.decode(
          m_PduSessionResourceReleaseCommandTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
long PduSessionResourceReleaseCommandTransfer::getChoiceOfCause() const {
  return m_CauseValue.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long PduSessionResourceReleaseCommandTransfer::getCause() const {
  return m_CauseValue.get();
}
}  // namespace oai::ngap
