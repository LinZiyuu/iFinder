/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduDnRequestContainer.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduDnRequestContainer::PduDnRequestContainer()
    : Type4NasIe(kIeiSmPduDnRequestContainer) {
  pdu_dn_request_container_ = nullptr;
  SetLengthIndicator(kPduDnRequestContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
PduDnRequestContainer::PduDnRequestContainer(
    const bstring& PduDnRequestContainer)
    : Type4NasIe(kIeiSmPduDnRequestContainer) {
  pdu_dn_request_container_ = bstrcpy(PduDnRequestContainer);
  SetLengthIndicator(
      (blength(pdu_dn_request_container_) >
       kPduDnRequestContainerContentMinimumLength) ?
          blength(pdu_dn_request_container_) :
          kPduDnRequestContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
PduDnRequestContainer::PduDnRequestContainer(bool iei)
    : Type4NasIe(), pdu_dn_request_container_() {
  if (iei) SetIei(kIeiSmPduDnRequestContainer);
  SetLengthIndicator(kPduDnRequestContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
PduDnRequestContainer::~PduDnRequestContainer() {}

//------------------------------------------------------------------------------
void PduDnRequestContainer::SetValue(const bstring& container) {
  pdu_dn_request_container_ = bstrcpy(container);
  SetLengthIndicator(
      (blength(pdu_dn_request_container_) >
       kPduDnRequestContainerContentMinimumLength) ?
          blength(pdu_dn_request_container_) :
          kPduDnRequestContainerContentMinimumLength);
}

//------------------------------------------------------------------------------
void PduDnRequestContainer::GetValue(bstring& container) const {
  container = bstrcpy(pdu_dn_request_container_);
}

//------------------------------------------------------------------------------
int PduDnRequestContainer::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Value
  int size = encode_bstring(
      pdu_dn_request_container_, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduDnRequestContainer::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kPduDnRequestContainerMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kPduDnRequestContainerMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // PduDnRequestContainer
  uint8_t ie_len = GetLengthIndicator();
  decode_bstring(
      &pdu_dn_request_container_, ie_len, (buf + decoded_size),
      len - decoded_size);
  decoded_size += ie_len;

  for (int i = 0; i < ie_len; i++) {
    oai::logger::logger_common::nas().debug(
        "Decoded value 0x%x", (uint8_t) pdu_dn_request_container_->data[i]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
