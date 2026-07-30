/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionModificationCommandReject.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionModificationCommandReject::PduSessionModificationCommandReject()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionModificationCommandReject) {
  ie_extended_protocol_configuration_options_ = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionModificationCommandReject::~PduSessionModificationCommandReject() {}

//------------------------------------------------------------------------------
uint32_t PduSessionModificationCommandReject::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_5gsm_cause_.GetIeLength();

  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommandReject::Set5gsmCause(
    const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = _5gsm_cause;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommandReject::Get5gsmCause(
    _5gsmCause& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommandReject::
    SetExtendedProtocolConfigurationOptions(
        const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommandReject::
    GetExtendedProtocolConfigurationOptions(
        std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionModificationCommandReject::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionModificationCommandReject message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GSM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionModificationCommandReject message len (%d)",
      encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionModificationCommandReject::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionModificationCommandReject message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  //
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gsm_cause_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    switch (octet) {
      case kIeiExtendedProtocolConfigurationOptions: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiExtendedProtocolConfigurationOptions);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_extended_protocol_configuration_options_, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        // TODO:
        if (flag) {
          oai::logger::logger_common::nas().warn(
              "Unknown IEI 0x%x, stop decoding...", octet);
          // Stop decoding
          octet = 0x00;
        }
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded PduSessionModificationCommandReject message len (%d)",
      decoded_size);
  return decoded_size;
}
