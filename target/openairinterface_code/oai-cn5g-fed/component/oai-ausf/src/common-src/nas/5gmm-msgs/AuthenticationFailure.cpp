/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationFailure.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationFailure::AuthenticationFailure()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kAuthenticationFailure) {
  ie_authentication_failure_parameter_ = std::nullopt;
}

//------------------------------------------------------------------------------
// AuthenticationFailure::~AuthenticationFailure() {}

//------------------------------------------------------------------------------
uint32_t AuthenticationFailure::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  msg_len += ie_5gmm_cause_.GetIeLength();
  if (ie_authentication_failure_parameter_.has_value())
    msg_len += ie_authentication_failure_parameter_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void AuthenticationFailure::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void AuthenticationFailure::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_.SetValue(value);
}

//------------------------------------------------------------------------------
uint8_t AuthenticationFailure::Get5gmmCause() const {
  return ie_5gmm_cause_.GetValue();
}

/*
//------------------------------------------------------------------------------
void AuthenticationFailure::SetAuthenticationFailureParameter(
    const uint8_t (&value)[kAuthenticationFailureParameterContentLength]) {
  ie_authentication_failure_parameter_ =
      std::make_optional<AuthenticationFailureParameter>(value);
}
bool AuthenticationFailure::GetAuthenticationFailureParameter(uint8_t
(&value)[kAuthenticationFailureParameterContentLength]) const{ if
(ie_authentication_failure_parameter_.has_value()) {
    ie_authentication_failure_parameter_.value().GetValue(value);
    return true;
  } else {
    return false;
  }
}
*/

//------------------------------------------------------------------------------
void AuthenticationFailure::SetAuthenticationFailureParameter(
    const bstring& value) {
  ie_authentication_failure_parameter_ =
      std::make_optional<AuthenticationFailureParameter>(value);
}

//------------------------------------------------------------------------------
bool AuthenticationFailure::GetAuthenticationFailureParameter(
    bstring& value) const {
  if (ie_authentication_failure_parameter_.has_value()) {
    ie_authentication_failure_parameter_.value().GetValue(value);
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
int AuthenticationFailure::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding AuthenticationFailure message");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GMM Cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Authentication Failure Parameter
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authentication_failure_parameter_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded AuthenticationFailure message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationFailure::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding AuthenticationFailure message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // 5GMM Cause
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gmm_cause_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
      case kIeiAuthenticationFailureParameter: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_authentication_failure_parameter_, buf, len, decoded_size,
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
      "Decoded AuthenticationFailure message len (%d)", decoded_size);
  return decoded_size;
}
