/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_29_503_SEEN
#define FILE_3GPP_29_503_SEEN

#include <stdint.h>

#include <string>

#include "3gpp_29.500.h"

struct udm_protocol_application_error {
  // Nudm_UEContextManagement
  static constexpr uint16_t UNKNOWN_5GS_SUBSCRIPTION  = 1;   // 403 Forbidden
  static constexpr uint16_t NO_PS_SUBSCRIPTION        = 2;   // 403 Forbidden
  static constexpr uint16_t ROAMING_NOT_ALLOWED       = 3;   // 403 Forbidden
  static constexpr uint16_t USER_NOT_FOUND            = 4;   // 404 Not Found
  static constexpr uint16_t CONTEXT_NOT_FOUND         = 5;   // 404 Not Found
  static constexpr uint16_t ACCESS_NOT_ALLOWED        = 6;   // 404 Not Found
  static constexpr uint16_t RAT_NOT_ALLOWED           = 7;   // 404 Not Found
  static constexpr uint16_t DNN_NOT_ALLOWED           = 8;   // 404 Not Found
  static constexpr uint16_t REAUTHENTICATION_REQUIRED = 9;   // 404 Not Found
  static constexpr uint16_t INVALID_GUAMI             = 10;  // 404 Not Found
  static constexpr uint16_t UNPROCESSABLE_REQUEST =
      11;  // 422 Unprocessable Entity

  // Nudm_UEAuthentication
  static constexpr uint16_t AUTHENTICATION_REJECTED = 12;  // 403 Forbidden
  static constexpr uint16_t SERVING_NETWORK_NOT_AUTHORIZED =
      13;  // 403 Forbidden
  static constexpr uint16_t UNSUPPORTED_PROTECTION_SCHEME =
      14;  // 501 Not Implemented
  static constexpr uint16_t INVALID_HN_PUBLIC_KEY_IDENTIFIER =
      15;                                                // 403 Forbidden
  static constexpr uint16_t INVALID_SCHEME_OUTPUT = 16;  // 403 Forbidden

  // Nudm_EventExposure
  static constexpr uint16_t MONITORING_NOT_ALLOWED = 17;  // 403 Forbidden
  static constexpr uint16_t UNSUPPORTED_MONITORING_EVENT_TYPE =
      18;  // 501 Not Implemented
  static constexpr uint16_t UNSUPPORTED_MONITORING_REPORT_OPTIONS =
      19;  // 501 Not Implemented

  // Nudm_ParameterProvision
  static constexpr uint16_t MODIFICATION_NOT_ALLOWED = 20;  // 403 Forbidden

  // Nudm_ SubscriberDataManagement
  static constexpr uint16_t NF_CONSUMER_REDIRECT_ONE_TXN =
      21;  // 307 Temporary Redirect
  static constexpr uint16_t DATA_NOT_FOUND             = 22;  // 404 Not Found
  static constexpr uint16_t GROUP_IDENTIFIER_NOT_FOUND = 23;  // 404 Not Found
  static constexpr uint16_t UNSUPPORTED_RESOURCE_URI =
      24;  // 501 Not Implemented
};

static std::string udm_protocol_application_error_to_string(uint16_t error) {
  std::string cause =
      oai::common::sbi::protocol_application_error_to_string(error);
  if (!cause.empty()) return cause;

  switch (error) {
    case udm_protocol_application_error::UNKNOWN_5GS_SUBSCRIPTION:
      return "UNKNOWN_5GS_SUBSCRIPTION";
    case udm_protocol_application_error::NO_PS_SUBSCRIPTION:
      return "NO_PS_SUBSCRIPTION";
    case udm_protocol_application_error::ROAMING_NOT_ALLOWED:
      return "ROAMING_NOT_ALLOWED";
    case udm_protocol_application_error::USER_NOT_FOUND:
      return "USER_NOT_FOUND";
    case udm_protocol_application_error::CONTEXT_NOT_FOUND:
      return "CONTEXT_NOT_FOUND";
    case udm_protocol_application_error::ACCESS_NOT_ALLOWED:
      return "ACCESS_NOT_ALLOWED";
    case udm_protocol_application_error::RAT_NOT_ALLOWED:
      return "RAT_NOT_ALLOWED";
    case udm_protocol_application_error::DNN_NOT_ALLOWED:
      return "DNN_NOT_ALLOWED";
    case udm_protocol_application_error::REAUTHENTICATION_REQUIRED:
      return "REAUTHENTICATION_REQUIRED";
    case udm_protocol_application_error::INVALID_GUAMI:
      return "INVALID_GUAMI";
    case udm_protocol_application_error::UNPROCESSABLE_REQUEST:
      return "UNPROCESSABLE_REQUEST";
    case udm_protocol_application_error::AUTHENTICATION_REJECTED:
      return "AUTHENTICATION_REJECTED";
    case udm_protocol_application_error::SERVING_NETWORK_NOT_AUTHORIZED:
      return "SERVING_NETWORK_NOT_AUTHORIZED";
    case udm_protocol_application_error::UNSUPPORTED_PROTECTION_SCHEME:
      return "UNSUPPORTED_PROTECTION_SCHEME";
    case udm_protocol_application_error::INVALID_HN_PUBLIC_KEY_IDENTIFIER:
      return "INVALID_HN_PUBLIC_KEY_IDENTIFIER";
    case udm_protocol_application_error::INVALID_SCHEME_OUTPUT:
      return "INVALID_SCHEME_OUTPUT";
    case udm_protocol_application_error::MONITORING_NOT_ALLOWED:
      return "MONITORING_NOT_ALLOWED";
    case udm_protocol_application_error::UNSUPPORTED_MONITORING_EVENT_TYPE:
      return "UNSUPPORTED_MONITORING_EVENT_TYPE";
    case udm_protocol_application_error::UNSUPPORTED_MONITORING_REPORT_OPTIONS:
      return "UNSUPPORTED_MONITORING_REPORT_OPTIONS";
    case udm_protocol_application_error::MODIFICATION_NOT_ALLOWED:
      return "MODIFICATION_NOT_ALLOWED";
    case udm_protocol_application_error::NF_CONSUMER_REDIRECT_ONE_TXN:
      return "NF_CONSUMER_REDIRECT_ONE_TXN";
    case udm_protocol_application_error::DATA_NOT_FOUND:
      return "DATA_NOT_FOUND";
    case udm_protocol_application_error::GROUP_IDENTIFIER_NOT_FOUND:
      return "GROUP_IDENTIFIER_NOT_FOUND";
    case udm_protocol_application_error::UNSUPPORTED_RESOURCE_URI:
      return "UNSUPPORTED_RESOURCE_URI";
  }
  return "UNKNOWN_UDM_PROTOCOL_APPLICATION_ERROR";
}

#endif  // FILE_3GPP_29_503_SEEN
