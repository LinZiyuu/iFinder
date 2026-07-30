/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_MIME_PARSER_HPP_SEEN
#define FILE_MIME_PARSER_HPP_SEEN

#include <unordered_map>
#include <string>
#include <vector>
#include <optional>

namespace oai::utils {

constexpr auto JSON_CONTENT_ID_MIME   = "root";
constexpr auto N1_SM_CONTENT_ID       = "n1SmMsg";
constexpr auto N2_SM_CONTENT_ID       = "n2msg";
constexpr auto N2_NRPPa_CONTENT_ID    = "n2NrppaMsg";
constexpr auto MIME_CONTENT_TYPE_NAS  = "application/vnd.3gpp.5gnas";
constexpr auto MIME_CONTENT_TYPE_NGAP = "application/vnd.3gpp.ngap";

enum class multipart_related_content_part_e { JSON = 0, NAS = 1, NGAP = 2 };

static const std::vector<std::string> multipart_related_content_part_e2str = {
    "JSON", "NAS", "NGAP"};

typedef struct mime_part {
  std::string content_type;
  std::string content_id;
  std::string body;
} mime_part;

class mime_parser {
 public:
  mime_parser() { mime_parts = {}; }
  /*
   * Parse the input string into different Mime parts
   * @param [const std::string &] str: input string
   * @return void
   */
  bool parse(const std::string& str);

  uint8_t parse(
      std::string input, std::string& jsonData, std::string& n1sm,
      std::string& n2sm);

  /*
   * Get content of a Mime part with corresponding Content ID
   * @param [const std::string&] content_id: Content ID
   * @param [std::string&] content: Mime content
   * @return true if content with Content ID exist, otherwise false
   */
  bool get(const std::string& content_id, std::string& content);

  /*
   * Get content of a Mime part with corresponding Content ID
   * @param [const std::string&] content_id: Content ID
   * @param [std::optional<std::string>&] content: Mime content
   * @return true if content with Content ID exist, otherwise false
   */
  void get(const std::string& content_id, std::optional<std::string>& content);

  /*
   * Get vector of Mime parts
   * @param [std::vector<mime_part> &] parts: store vector of Mime parts
   * @return void
   */
  void get_mime_parts(std::unordered_map<std::string, mime_part>& parts) const;

  /*
   * Represent a string as hex
   * @param [const std::string&] str: input string
   * @return String represents string in hex format
   */
  static unsigned char* format_string_as_hex(const std::string& str);

  /*
   * Create HTTP body content for multipart/related message
   * @param [std::string] body: Body of the created message
   * @param [std::string] json_part: Json part of multipart/related msg
   * @param [std::string] boundary: Boundary of multipart/related msg
   * @param [std::string] n1_message: N1 (NAS) part
   * @param [std::string] n2_message: N2 (NGAP) part
   * @return void
   */
  void static create_multipart_related_content(
      std::string& body, const std::string& json_part,
      const std::string boundary, const std::string& n1_message,
      const std::string& n2_message,
      std::string json_format = "application/json");

  /*
   * Create HTTP body content for multipart/related message
   * @param [std::string] body: Body of the created message
   * @param [std::string] json_part: Json part of multipart/related msg
   * @param [std::string] boundary: Boundary of multipart/related msg
   * @param [std::string] message: N1 (NAS) or N2 (NGAP) part
   * @param [uint8_t] content_type: 1 for NAS content, else NGAP content
   * @return void
   */
  void static create_multipart_related_content(
      std::string& body, const std::string& json_part,
      const std::string boundary, const std::string& message,
      const multipart_related_content_part_e content_type,
      std::string json_format = "application/json");

 private:
  std::unordered_map<std::string, mime_part> mime_parts;
};
}  // namespace oai::utils

#endif /* FILE_MIME_PARSER_HPP_SEEN */
