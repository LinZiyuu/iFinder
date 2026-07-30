/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceNotifyReleasedTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceNotifyReleasedTransfer::
    PduSessionResourceNotifyReleasedTransfer() {
  m_PduSessionResourceNotifyReleasedTransferIe =
      (Ngap_PDUSessionResourceNotifyReleasedTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceNotifyReleasedTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceNotifyReleasedTransfer::
    ~PduSessionResourceNotifyReleasedTransfer() {
  // if(m_PduSessionResourceNotifyReleasedTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,m_PduSessionResourceNotifyReleasedTransferIe);
  // if (m_PduSessionResourceNotifyReleasedTransferIe)
  // free(m_PduSessionResourceNotifyReleasedTransferIe);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyReleasedTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceNotifyReleasedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyReleasedTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceNotifyReleasedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyReleasedTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceNotifyReleasedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyReleasedTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceNotifyReleasedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyReleasedTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PduSessionResourceNotifyReleasedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
long PduSessionResourceNotifyReleasedTransfer::getChoiceOfCause() const {
  return m_CauseValue.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long PduSessionResourceNotifyReleasedTransfer::getCause() const {
  return m_CauseValue.get();
}

//------------------------------------------------------------------------------
int PduSessionResourceNotifyReleasedTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceNotifyReleasedTransfer,
      m_PduSessionResourceNotifyReleasedTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceNotifyReleasedTransfer, NULL,
      m_PduSessionResourceNotifyReleasedTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceNotifyReleasedTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceNotifyReleasedTransfer,
      (void**) &m_PduSessionResourceNotifyReleasedTransferIe, buf, bufSize);

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
  // &asn_DEF_Ngap_PDUSessionResourceNotifyReleasedTransfer,
  // m_PduSessionResourceNotifyReleasedTransferIe);

  if (!m_CauseValue.decode(
          m_PduSessionResourceNotifyReleasedTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }
  return true;
}

}  // namespace oai::ngap
