/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeContextSuspendRequestTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeContextSuspendRequestTransfer::UeContextSuspendRequestTransfer() {
  m_UeContextSuspendRequestTransferIe =
      (Ngap_UEContextSuspendRequestTransfer_t*) calloc(
          1, sizeof(Ngap_UEContextSuspendRequestTransfer_t));
}

//------------------------------------------------------------------------------
UeContextSuspendRequestTransfer::~UeContextSuspendRequestTransfer() {}

//------------------------------------------------------------------------------
int UeContextSuspendRequestTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_UEContextSuspendRequestTransfer,
      m_UeContextSuspendRequestTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_UEContextSuspendRequestTransfer, NULL,
      m_UeContextSuspendRequestTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded %d", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool UeContextSuspendRequestTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_UEContextSuspendRequestTransfer,
      (void**) &m_UeContextSuspendRequestTransferIe, buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug(
        "Decoded UeContextSuspendRequestTransfer successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug(
        "Failure to decode UeContextSuspendRequestTransfer data");
    // return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode: %d", rc.consumed);

  return true;
}

}  // namespace oai::ngap
