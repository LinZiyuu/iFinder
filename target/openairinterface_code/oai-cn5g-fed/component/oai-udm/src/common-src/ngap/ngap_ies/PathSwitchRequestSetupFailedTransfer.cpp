/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PathSwitchRequestSetupFailedTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PathSwitchRequestSetupFailedTransfer::PathSwitchRequestSetupFailedTransfer() {
  m_PathSwitchRequestSetupFailedTransferIe =
      (Ngap_PathSwitchRequestSetupFailedTransfer_t*) calloc(
          1, sizeof(Ngap_PathSwitchRequestSetupFailedTransfer_t));
}

//------------------------------------------------------------------------------
PathSwitchRequestSetupFailedTransfer::~PathSwitchRequestSetupFailedTransfer() {
  // if(m_PathSwitchRequestSetupFailedTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_PathSwitchRequestSetupFailedTransfer,m_PathSwitchRequestSetupFailedTransferIe);
  // if (m_PathSwitchRequestSetupFailedTransferIe)
  // free(m_PathSwitchRequestSetupFailedTransferIe);
}

//------------------------------------------------------------------------------
void PathSwitchRequestSetupFailedTransfer::setCauseRadioNetwork(
    e_Ngap_CauseRadioNetwork causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_radioNetwork);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PathSwitchRequestSetupFailedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode CauseRadioNetwork IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PathSwitchRequestSetupFailedTransfer::setCauseTransport(
    e_Ngap_CauseTransport causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_transport);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PathSwitchRequestSetupFailedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseTransport IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PathSwitchRequestSetupFailedTransfer::setCauseNas(
    e_Ngap_CauseNas causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_nas);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PathSwitchRequestSetupFailedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseNas IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PathSwitchRequestSetupFailedTransfer::setCauseProtocol(
    e_Ngap_CauseProtocol causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_protocol);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PathSwitchRequestSetupFailedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseProtocol IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PathSwitchRequestSetupFailedTransfer::setCauseMisc(
    e_Ngap_CauseMisc causeValue) {
  m_CauseValue.setChoiceOfCause(Ngap_Cause_PR_misc);
  m_CauseValue.set(causeValue);

  int ret =
      m_CauseValue.encode(m_PathSwitchRequestSetupFailedTransferIe->cause);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode CauseMisc IE error");
    return;
  }
}

//------------------------------------------------------------------------------
long PathSwitchRequestSetupFailedTransfer::getChoiceOfCause() const {
  return m_CauseValue.getChoiceOfCause();
}

//------------------------------------------------------------------------------
long PathSwitchRequestSetupFailedTransfer::getCause() const {
  return m_CauseValue.get();
}

//------------------------------------------------------------------------------
int PathSwitchRequestSetupFailedTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PathSwitchRequestSetupFailedTransfer,
      m_PathSwitchRequestSetupFailedTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PathSwitchRequestSetupFailedTransfer, NULL,
      m_PathSwitchRequestSetupFailedTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PathSwitchRequestSetupFailedTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PathSwitchRequestSetupFailedTransfer,
      (void**) &m_PathSwitchRequestSetupFailedTransferIe, buf, bufSize);

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
  // &asn_DEF_Ngap_PathSwitchRequestSetupFailedTransfer,
  // m_PathSwitchRequestSetupFailedTransferIe);

  if (!m_CauseValue.decode(m_PathSwitchRequestSetupFailedTransferIe->cause)) {
    oai::logger::logger_common::ngap().error("Decode Cause IE error");
    return false;
  }
  return true;
}

}  // namespace oai::ngap
