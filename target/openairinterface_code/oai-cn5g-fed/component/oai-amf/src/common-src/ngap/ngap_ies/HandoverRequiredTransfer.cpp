/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverRequiredTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverRequiredTransfer::HandoverRequiredTransfer() {
  m_HandoverRquiredTransferIe = (Ngap_HandoverRequiredTransfer_t*) calloc(
      1, sizeof(Ngap_HandoverRequiredTransfer_t));
  m_DirectForwardingPathAvailability = std::nullopt;
}

//------------------------------------------------------------------------------
HandoverRequiredTransfer::~HandoverRequiredTransfer() {}

//------------------------------------------------------------------------------
void HandoverRequiredTransfer::setDirectForwardingPathAvailability(
    const Ngap_DirectForwardingPathAvailability_t&
        directForwardingPathAvailability) {
  m_DirectForwardingPathAvailability =
      std::make_optional<Ngap_DirectForwardingPathAvailability_t>(
          directForwardingPathAvailability);
  m_HandoverRquiredTransferIe->directForwardingPathAvailability =
      (Ngap_DirectForwardingPathAvailability_t*) calloc(
          1, sizeof(Ngap_DirectForwardingPathAvailability_t));
  *m_HandoverRquiredTransferIe->directForwardingPathAvailability =
      directForwardingPathAvailability;
}

//------------------------------------------------------------------------------
bool HandoverRequiredTransfer::getDirectForwardingPathAvailability(
    long& directForwardingPathAvailability) const {
  if (m_DirectForwardingPathAvailability.has_value()) {
    directForwardingPathAvailability =
        (long) m_DirectForwardingPathAvailability.value();
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
std::optional<long>
HandoverRequiredTransfer::getDirectForwardingPathAvailability() const {
  return m_DirectForwardingPathAvailability;
}
//------------------------------------------------------------------------------
int HandoverRequiredTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_HandoverRequiredTransfer, m_HandoverRquiredTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_HandoverRequiredTransfer, NULL, m_HandoverRquiredTransferIe,
      buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded %d", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool HandoverRequiredTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Ngap_HandoverRequiredTransfer,
      (void**) &m_HandoverRquiredTransferIe, buf, bufSize);
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

  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer,
  // pduSessionResourceSetupResponseTransferIEs);
  if (m_HandoverRquiredTransferIe->directForwardingPathAvailability) {
    Ngap_DirectForwardingPathAvailability_t* directForwardingPathAvailability =
        new Ngap_DirectForwardingPathAvailability_t;
    directForwardingPathAvailability =
        m_HandoverRquiredTransferIe->directForwardingPathAvailability;
  }

  return true;
}

}  // namespace oai::ngap
