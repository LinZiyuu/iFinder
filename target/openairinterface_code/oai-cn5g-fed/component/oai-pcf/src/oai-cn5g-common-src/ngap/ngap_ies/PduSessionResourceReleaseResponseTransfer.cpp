/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleaseResponseTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleaseResponseTransfer::
    PduSessionResourceReleaseResponseTransfer() {
  m_PduSessionResourceReleaseResponseTransferIe =
      (Ngap_PDUSessionResourceReleaseResponseTransfer_t*) calloc(
          1, sizeof(Ngap_PDUSessionResourceReleaseResponseTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceReleaseResponseTransfer::
    ~PduSessionResourceReleaseResponseTransfer() {
  // if(m_PduSessionResourceReleaseResponseTransferIe)
  // ASN_STRUCT_FREE(asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer,m_PduSessionResourceReleaseResponseTransferIe);
  // if (m_PduSessionResourceReleaseResponseTransferIe)
  // free(m_PduSessionResourceReleaseResponseTransferIe);
}

//------------------------------------------------------------------------------
int PduSessionResourceReleaseResponseTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer,
      m_PduSessionResourceReleaseResponseTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer, NULL,
      m_PduSessionResourceReleaseResponseTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseResponseTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer,
      (void**) &m_PduSessionResourceReleaseResponseTransferIe, buf, bufSize);

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
  // &asn_DEF_Ngap_PDUSessionResourceReleaseResponseTransfer,
  // m_PduSessionResourceReleaseResponseTransferIe);

  // TODO: Secondary RAT Usage Information (Optional)

  return true;
}
}  // namespace oai::ngap
