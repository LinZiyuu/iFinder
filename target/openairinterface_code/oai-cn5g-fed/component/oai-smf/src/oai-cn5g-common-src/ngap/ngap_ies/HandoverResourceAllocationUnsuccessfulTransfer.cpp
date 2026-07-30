/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverResourceAllocationUnsuccessfulTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverResourceAllocationUnsuccessfulTransfer::
    HandoverResourceAllocationUnsuccessfulTransfer() {
  m_HandoverResourceAllocationUnsuccessfulTransferIe =
      (Ngap_HandoverResourceAllocationUnsuccessfulTransfer_t*) calloc(
          1, sizeof(Ngap_HandoverResourceAllocationUnsuccessfulTransfer_t));
}

//------------------------------------------------------------------------------
HandoverResourceAllocationUnsuccessfulTransfer::
    ~HandoverResourceAllocationUnsuccessfulTransfer() {
  // if(m_HandoverResourceAllocationUnsuccessfulTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_PDUSessionResourceReleaseCommandTransfer,m_HandoverResourceAllocationUnsuccessfulTransferIe);
  // if (m_HandoverResourceAllocationUnsuccessfulTransferIe)
  // free(m_HandoverResourceAllocationUnsuccessfulTransferIe);
}

//------------------------------------------------------------------------------
void HandoverResourceAllocationUnsuccessfulTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_CauseValue.set(causeValue);

  int ret = m_CauseValue.encode(
      m_HandoverResourceAllocationUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverResourceAllocationUnsuccessfulTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_CauseValue.set(causeValue);

  int ret = m_CauseValue.encode(
      m_HandoverResourceAllocationUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverResourceAllocationUnsuccessfulTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_CauseValue.set(causeValue);

  int ret = m_CauseValue.encode(
      m_HandoverResourceAllocationUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverResourceAllocationUnsuccessfulTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_CauseValue.set(causeValue);

  int ret = m_CauseValue.encode(
      m_HandoverResourceAllocationUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverResourceAllocationUnsuccessfulTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_CauseValue.set(causeValue);

  int ret = m_CauseValue.encode(
      m_HandoverResourceAllocationUnsuccessfulTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
long HandoverResourceAllocationUnsuccessfulTransfer::getChoiceOfCause() const {
  return m_CauseValue.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long HandoverResourceAllocationUnsuccessfulTransfer::getCause() const {
  return m_CauseValue.get();
}

//------------------------------------------------------------------------------
int HandoverResourceAllocationUnsuccessfulTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_HandoverResourceAllocationUnsuccessfulTransfer,
      m_HandoverResourceAllocationUnsuccessfulTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_HandoverResourceAllocationUnsuccessfulTransfer, NULL,
      m_HandoverResourceAllocationUnsuccessfulTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool HandoverResourceAllocationUnsuccessfulTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_HandoverResourceAllocationUnsuccessfulTransfer,
      (void**) &m_HandoverResourceAllocationUnsuccessfulTransferIe, buf,
      bufSize);

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
  // &asn_DEF_Ngap_HandoverResourceAllocationUnsuccessfulTransfer,
  // m_HandoverResourceAllocationUnsuccessfulTransferIe);

  if (!m_CauseValue.decode(
          m_HandoverResourceAllocationUnsuccessfulTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }
  return true;
}

}  // namespace oai::ngap
