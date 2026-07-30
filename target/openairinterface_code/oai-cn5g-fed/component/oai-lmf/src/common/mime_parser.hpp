/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_MIME_PARSER_HPP_SEEN
#define FILE_MIME_PARSER_HPP_SEEN
#include <string>
#include <map>
#include <vector>

enum class multipart_related_content_part_e {
  JSON  = 0,
  NAS   = 1,
  NGAP  = 2,
  LPP   = 3,
  NRPPA = 4
};

static const std::vector<std::string> multipart_related_content_part_e2str = {
    "JSON", "NAS", "NGAP", "LPP", "NRPPA"};

typedef struct mime_part {
  std::string content_type;
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

  /*
   * Get vector of Mime parts
   * @param [std::vector<mime_part> &] parts: store vector of Mime parts
   * @return void
   */
  void get_mime_parts(std::vector<mime_part>& parts) const;

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
  std::vector<mime_part> mime_parts;
};

#endif /* FILE_MIME_PARSER_HPP_SEEN */
