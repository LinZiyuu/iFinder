/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_29_500_SEEN
#define FILE_3GPP_29_500_SEEN

#include <stdint.h>

#include <string>

namespace oai::common::sbi {

enum class method_e { POST, GET, PUT, PATCH, DELETE, OPTIONS };

static std::string method_to_string(method_e method) {
  switch (method) {
    case method_e::POST:
      return "POST";
    case method_e::GET:
      return "GET";
    case method_e::PUT:
      return "PUT";
    case method_e::PATCH:
      return "PATCH";
    case method_e::DELETE:
      return "DELETE";
    case method_e::OPTIONS:
      return "OPTIONS";
  }
  return "";
}

// use constexpr to avoid casting from/to int
struct http_status_code {
  static constexpr uint16_t NO_RESPONSE            = 0;
  static constexpr uint16_t CONTINUE               = 100;
  static constexpr uint16_t OK                     = 200;
  static constexpr uint16_t CREATED                = 201;
  static constexpr uint16_t ACCEPTED               = 202;
  static constexpr uint16_t NO_CONTENT             = 204;
  static constexpr uint16_t MULTIPLE_CHOICES       = 300;
  static constexpr uint16_t SEE_OTHER              = 303;
  static constexpr uint16_t TEMPORARY_REDIRECT     = 307;
  static constexpr uint16_t PERMANENT_REDIRECT     = 308;
  static constexpr uint16_t BAD_REQUEST            = 400;
  static constexpr uint16_t UNAUTHORIZED           = 401;
  static constexpr uint16_t FORBIDDEN              = 403;
  static constexpr uint16_t NOT_FOUND              = 404;
  static constexpr uint16_t METHOD_NOT_ALLOWED     = 405;
  static constexpr uint16_t NOT_ACCEPTABLE         = 406;
  static constexpr uint16_t REQUEST_TIMEOUT        = 408;
  static constexpr uint16_t CONFLICT               = 409;
  static constexpr uint16_t GONE                   = 410;
  static constexpr uint16_t LENGTH_REQUIRED        = 411;
  static constexpr uint16_t PRECONDITION_FAILED    = 412;
  static constexpr uint16_t PAYLOAD_TOO_LARGE      = 413;
  static constexpr uint16_t URI_TOO_LONG           = 414;
  static constexpr uint16_t UNSUPPORTED_MEDIA_TYPE = 415;
  static constexpr uint16_t TOO_MANY_REQUESTS      = 429;
  static constexpr uint16_t INTERNAL_SERVER_ERROR  = 500;
  static constexpr uint16_t NOT_IMPLEMENTED        = 501;
  static constexpr uint16_t BAD_GATEWAY            = 502;
  static constexpr uint16_t SERVICE_UNAVAILABLE    = 503;
  static constexpr uint16_t GATEWAY_TIMEOUT        = 504;
};

struct protocol_application_error {
  // For 400 Bad Request
  static constexpr uint16_t INVALID_API                     = 0;
  static constexpr uint16_t INVALID_MSG_FORMAT              = 1;
  static constexpr uint16_t INVALID_QUERY_PARAM             = 2;
  static constexpr uint16_t MANDATORY_QUERY_PARAM_INCORRECT = 3;
  static constexpr uint16_t OPTIONAL_QUERY_PARAM_INCORRECT  = 4;
  static constexpr uint16_t MANDATORY_QUERY_PARAM_MISSING   = 5;
  static constexpr uint16_t MANDATORY_IE_INCORRECT          = 6;
  static constexpr uint16_t OPTIONAL_IE_INCORRECT           = 7;
  static constexpr uint16_t MANDATORY_IE_MISSING            = 8;
  static constexpr uint16_t UNSPECIFIED_MSG_FAILURE         = 9;
  // For 403 Forbidden
  static constexpr uint16_t MODIFICATION_NOT_ALLOWED = 10;
  // For 404 Not Found
  static constexpr uint16_t SUBSCRIPTION_NOT_FOUND           = 11;
  static constexpr uint16_t RESOURCE_URI_STRUCTURE_NOT_FOUND = 12;
  // For 411 Length Required
  static constexpr uint16_t INCORRECT_LENGTH = 13;
  // For 429 Too Many Requests
  static constexpr uint16_t NF_CONGESTION_RISK = 14;
  // For 500 Internal Server Error
  static constexpr uint16_t INSUFFICIENT_RESOURCES = 15;
  static constexpr uint16_t UNSPECIFIED_NF_FAILURE = 16;
  static constexpr uint16_t SYSTEM_FAILURE         = 17;
  // 503 Service Unavailable
  static constexpr uint16_t NF_CONGESTION = 18;
};

static std::string protocol_application_error_to_string(uint16_t error) {
  switch (error) {
    case protocol_application_error::INVALID_API:
      return "INVALID_API";
    case protocol_application_error::INVALID_MSG_FORMAT:
      return "INVALID_MSG_FORMAT";
    case protocol_application_error::INVALID_QUERY_PARAM:
      return "INVALID_QUERY_PARAM";
    case protocol_application_error::MANDATORY_QUERY_PARAM_INCORRECT:
      return "MANDATORY_QUERY_PARAM_INCORRECT";
    case protocol_application_error::OPTIONAL_QUERY_PARAM_INCORRECT:
      return "OPTIONAL_QUERY_PARAM_INCORRECT";
    case protocol_application_error::MANDATORY_QUERY_PARAM_MISSING:
      return "MANDATORY_QUERY_PARAM_MISSING";
    case protocol_application_error::MANDATORY_IE_INCORRECT:
      return "MANDATORY_IE_INCORRECT";
    case protocol_application_error::OPTIONAL_IE_INCORRECT:
      return "OPTIONAL_IE_INCORRECT";
    case protocol_application_error::MANDATORY_IE_MISSING:
      return "MANDATORY_IE_MISSING";
    case protocol_application_error::UNSPECIFIED_MSG_FAILURE:
      return "UNSPECIFIED_MSG_FAILURE";
    case protocol_application_error::MODIFICATION_NOT_ALLOWED:
      return "MODIFICATION_NOT_ALLOWED";
    case protocol_application_error::SUBSCRIPTION_NOT_FOUND:
      return "SUBSCRIPTION_NOT_FOUND";
    case protocol_application_error::RESOURCE_URI_STRUCTURE_NOT_FOUND:
      return "RESOURCE_URI_STRUCTURE_NOT_FOUND";
    case protocol_application_error::INCORRECT_LENGTH:
      return "INCORRECT_LENGTH";
    case protocol_application_error::NF_CONGESTION_RISK:
      return "NF_CONGESTION_RISK";
    case protocol_application_error::INSUFFICIENT_RESOURCES:
      return "INSUFFICIENT_RESOURCES";
    case protocol_application_error::UNSPECIFIED_NF_FAILURE:
      return "UNSPECIFIED_NF_FAILURE";
    case protocol_application_error::SYSTEM_FAILURE:
      return "SYSTEM_FAILURE";
    case protocol_application_error::NF_CONGESTION:
      return "NF_CONGESTION";
  }
  return {};
}

}  // namespace oai::common::sbi

#endif  // FILE_3GPP_29_500_SEEN
