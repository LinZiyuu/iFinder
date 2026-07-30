/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecondaryRatDataUsageReportTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SecondaryRatDataUsageReportTransfer::SecondaryRatDataUsageReportTransfer() {
  m_SecondaryRatDataUsageReportTransferIe =
      (Ngap_SecondaryRATDataUsageReportTransfer_t*) calloc(
          1, sizeof(Ngap_SecondaryRATDataUsageReportTransfer_t));
}

//------------------------------------------------------------------------------
SecondaryRatDataUsageReportTransfer::~SecondaryRatDataUsageReportTransfer() {
  // if(m_SecondaryRatDataUsageReportTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_SecondaryRATDataUsageReportTransfer,m_SecondaryRatDataUsageReportTransferIe);
  // if (m_SecondaryRatDataUsageReportTransferIe)
  // free(m_SecondaryRatDataUsageReportTransferIe);
}

//------------------------------------------------------------------------------
int SecondaryRatDataUsageReportTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_SecondaryRATDataUsageReportTransfer,
      m_SecondaryRatDataUsageReportTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_SecondaryRATDataUsageReportTransfer, NULL,
      m_SecondaryRatDataUsageReportTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool SecondaryRatDataUsageReportTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_SecondaryRATDataUsageReportTransfer,
      (void**) &m_SecondaryRatDataUsageReportTransferIe, buf, bufSize);

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
  // &asn_DEF_Ngap_SecondaryRATDataUsageReportTransfer,
  // m_SecondaryRatDataUsageReportTransferIe);

  // TODO: Secondary RAT Usage Information (Optional)

  return true;
}
}  // namespace oai::ngap
