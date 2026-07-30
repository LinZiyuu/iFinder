/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "mime_parser.hpp"
#include "logger_base.hpp"
#include "conversions.hpp"
#include "utils.hpp"
#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string.hpp>

using namespace oai::utils;

//------------------------------------------------------------------------------
bool mime_parser::parse(const std::string& str) {
  std::string str_tmp = str;
  std::string CRLF    = "\r\n";
  oai::logger::logger_common::common().debug(
      "Parsing the message with the Simple Parser");

  // Convert all Content-Type/Content-Id to lowercase content-type/content-id
  boost::algorithm::ireplace_all(str_tmp, "Content-Type", "content-type");
  boost::algorithm::ireplace_all(str_tmp, "Content-Id", "content-id");

  // find boundary
  std::size_t content_type_pos = str_tmp.find("content-type");  // first part

  // For normal message -> don't need to parse (number of parts = 0)
  if ((content_type_pos <= 4) or (content_type_pos == std::string::npos))
    return true;

  std::string boundary_str =
      str_tmp.substr(2, content_type_pos - 4);  // 2 for -- and 2 for CRLF
  oai::logger::logger_common::common().debug(
      "Boundary: %s", boundary_str.c_str());
  std::string boundary_full = "--" + boundary_str + CRLF;
  std::string last_boundary = "--" + boundary_str + "--";

  std::size_t crlf_pos           = str_tmp.find(CRLF, content_type_pos);
  std::size_t boundary_pos       = str_tmp.find(boundary_full);
  std::size_t boundary_last_post = str_tmp.find(last_boundary);

  while (boundary_pos < boundary_last_post) {
    mime_part p      = {};
    content_type_pos = str_tmp.find("content-type", boundary_pos);
    crlf_pos         = str_tmp.find(CRLF, content_type_pos);
    if ((content_type_pos == std::string::npos) or
        (crlf_pos == std::string::npos))
      break;
    p.content_type = str_tmp.substr(
        content_type_pos + 14, crlf_pos - (content_type_pos + 14));
    oai::logger::logger_common::common().debug(
        "Content Type: %s", p.content_type.c_str());

    if (boost::iequals(p.content_type, "application/json") or
        boost::iequals(p.content_type, "application/problem+json")) {
      p.content_id = JSON_CONTENT_ID_MIME;
      crlf_pos =
          str_tmp.find(CRLF + CRLF, content_type_pos);  // beginning of content
    } else {
      std::size_t content_id_pos = str_tmp.find("content-id", boundary_pos);

      if ((content_id_pos == std::string::npos)) {
        oai::logger::logger_common::common().warn("There's no content id");
        return false;
      } else {
        crlf_pos = str_tmp.find(CRLF, content_id_pos);
        if (crlf_pos == std::string::npos) return false;
        p.content_id =
            str_tmp.substr(content_id_pos + 12, crlf_pos - content_id_pos - 12);
        crlf_pos =
            str_tmp.find(CRLF + CRLF, content_id_pos);  // beginning of content
      }
    }

    oai::logger::logger_common::common().debug(
        "Content Id: %s", p.content_id.c_str());

    boundary_pos = str_tmp.find(boundary_full, crlf_pos);
    if (boundary_pos == std::string::npos) {
      boundary_pos = str_tmp.find(last_boundary, crlf_pos);
    }
    if (boundary_pos > 0) {
      p.body = str_tmp.substr(crlf_pos + 4, boundary_pos - 2 - (crlf_pos + 4));
      oai::logger::logger_common::common().debug("Body: %s", p.body.c_str());
      mime_parts[p.content_id] = p;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
uint8_t mime_parser::parse(
    std::string input, std::string& jsonData, std::string& n1sm,
    std::string& n2sm) {
  if (!parse(input)) return 0;
  uint8_t size = mime_parts.size();
  if (mime_parts.count(JSON_CONTENT_ID_MIME) != 0) {
    jsonData = mime_parts[JSON_CONTENT_ID_MIME].body;
  }
  if (mime_parts.count(N1_SM_CONTENT_ID) != 0) {
    n1sm = mime_parts[N1_SM_CONTENT_ID].body;
  }
  if (mime_parts.count(N2_SM_CONTENT_ID) != 0) {
    n2sm = mime_parts[N2_SM_CONTENT_ID].body;
  }
  return size;
}

//------------------------------------------------------------------------------
bool mime_parser::get(const std::string& content_id, std::string& content) {
  if (mime_parts.count(content_id) != 0) {
    content = mime_parts[content_id].body;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void mime_parser::get(
    const std::string& content_id, std::optional<std::string>& content) {
  if (mime_parts.count(content_id) != 0) {
    content = std::make_optional<std::string>(mime_parts[content_id].body);
  }
}

//------------------------------------------------------------------------------
void mime_parser::get_mime_parts(
    std::unordered_map<std::string, mime_part>& parts) const {
  for (auto it : mime_parts) {
    parts[it.first] = it.second;
  }
}

//------------------------------------------------------------------------------
unsigned char* mime_parser::format_string_as_hex(const std::string& str) {
  unsigned int str_len = str.length();
  char* data           = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) str.c_str(), str_len);

  unsigned char* data_hex = (uint8_t*) malloc(str_len / 2 + 1);
  oai::utils::conv::ascii_to_hex(data_hex, (const char*) data);

  oai::logger::logger_common::common().debug(
      "Input string (%d bytes): %s ", str_len, str.c_str());
  oai::logger::logger_common::common().debug("Data (formatted):");
  if (oai::logger::logger_common::should_log(spdlog::level::debug)) {
    for (int i = 0; i < str_len / 2; i++) printf(" %02x ", data_hex[i]);
    printf("\n");
  }

  // free memory
  oai::utils::utils::free_wrapper((void**) &data);

  return data_hex;
}

//------------------------------------------------------------------------------
void mime_parser::create_multipart_related_content(
    std::string& body, const std::string& json_part, const std::string boundary,
    const std::string& n1_message, const std::string& n2_message,
    std::string json_format) {
  // format string as hex
  unsigned char* n1_msg_hex = format_string_as_hex(n1_message);
  unsigned char* n2_msg_hex = format_string_as_hex(n2_message);

  std::string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: " + json_format + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  body.append("Content-Type: ")
      .append(MIME_CONTENT_TYPE_NAS)
      .append(CRLF)
      .append("Content-Id: ")
      .append(N1_SM_CONTENT_ID + CRLF);
  body.append(CRLF);
  body.append(std::string((char*) n1_msg_hex, n1_message.length() / 2) + CRLF);
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: ")
      .append(MIME_CONTENT_TYPE_NGAP + CRLF)
      .append("Content-Id: ")
      .append(N2_SM_CONTENT_ID + CRLF);
  body.append(CRLF);
  body.append(std::string((char*) n2_msg_hex, n2_message.length() / 2) + CRLF);
  body.append("--" + boundary + "--" + CRLF);

  // free memory
  oai::utils::utils::free_wrapper((void**) &n1_msg_hex);
  oai::utils::utils::free_wrapper((void**) &n2_msg_hex);
}

//------------------------------------------------------------------------------
void mime_parser::create_multipart_related_content(
    std::string& body, const std::string& json_part, const std::string boundary,
    const std::string& message,
    const multipart_related_content_part_e content_type,
    std::string json_format) {
  // format string as hex
  unsigned char* msg_hex = format_string_as_hex(message);

  std::string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: " + json_format + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  if (content_type == multipart_related_content_part_e::NAS) {  // NAS
    body.append("Content-Type: ")
        .append(MIME_CONTENT_TYPE_NAS + CRLF)
        .append("Content-Id: ")
        .append(N1_SM_CONTENT_ID + CRLF);
  } else if (content_type == multipart_related_content_part_e::NGAP) {  // NGAP
    body.append("Content-Type: ")
        .append(MIME_CONTENT_TYPE_NGAP + CRLF)
        .append("Content-Id: ")
        .append(N2_SM_CONTENT_ID + CRLF);
  }
  body.append(CRLF);
  body.append(std::string((char*) msg_hex, message.length() / 2) + CRLF);
  body.append("--" + boundary + "--" + CRLF);

  // free memory
  oai::utils::utils::free_wrapper((void**) &msg_hex);
}
