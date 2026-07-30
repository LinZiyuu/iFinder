/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RegistrationComplete.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
RegistrationComplete::RegistrationComplete()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kRegistrationComplete) {
  ie_sor_transparent_container_ = std::nullopt;
}

//------------------------------------------------------------------------------
RegistrationComplete::~RegistrationComplete() {}

//------------------------------------------------------------------------------
uint32_t RegistrationComplete::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  if (ie_sor_transparent_container_.has_value())
    msg_len += ie_sor_transparent_container_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void RegistrationComplete::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void RegistrationComplete::SetSorTransparentContainer(
    uint8_t header,
    const uint8_t (&value)[kSorTransparentContainerIeMacLength]) {
  ie_sor_transparent_container_ =
      std::make_optional<SorTransparentContainer>(header, value);
}

//------------------------------------------------------------------------------
int RegistrationComplete::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding RegistrationComplete message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  if ((encoded_ie_size = NasHelper::Encode(
           ie_sor_transparent_container_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded RegistrationComplete message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int RegistrationComplete::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding RegistrationComplete message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  while ((octet != 0x0)) {
    switch (octet) {
      case kIeiSorTransparentContainer: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiSorTransparentContainer);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_sor_transparent_container_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        oai::logger::logger_common::nas().warn(
            "Unknown IEI 0x%x, stop decoding...", octet);
        // Stop decoding
        octet = 0x00;
      } break;
    }
  }
  oai::logger::logger_common::nas().debug(
      "Decoded RegistrationComplete message (len %d)", decoded_size);
  return decoded_size;
}
