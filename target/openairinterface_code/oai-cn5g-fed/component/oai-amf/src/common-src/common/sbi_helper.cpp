/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "sbi_helper.hpp"

#include <fmt/format.h>
#include <regex>

using namespace oai::common::sbi;

//---------------------------------------------------------------------------------------------
void sbi_helper::get_nrf_nfm_api_root(
    const nf_addr_t& nrf_addr, std::string& api_root) {
  api_root = nrf_addr.uri_root + sbi_helper::NrfNfmBase + nrf_addr.api_version;
}

//---------------------------------------------------------------------------------------------
void sbi_helper::get_nrf_nfm_api_root(
    const oai::config::sbi_interface& nrf, bool enable_tls,
    std::string& api_root) {
  api_root =
      nrf.get_url(enable_tls) + sbi_helper::NrfNfmBase + nrf.get_api_version();
}

//---------------------------------------------------------------------------------------------
std::string sbi_helper::get_nrf_nfm_api_root(
    const oai::config::sbi_interface& nrf, bool enable_tls) {
  return nrf.get_url(enable_tls) + sbi_helper::NrfNfmBase +
         nrf.get_api_version();
}

//---------------------------------------------------------------------------------------------
void sbi_helper::get_nrf_nf_instance_uri(
    const nf_addr_t& nrf_addr, const std::string& nf_instance,
    std::string& uri) {
  std::string nrf_api_root = {};
  get_nrf_nfm_api_root(nrf_addr, nrf_api_root);
  std::string path_nf_instance_id = {};
  get_fmt_format_form(
      sbi_helper::NrfNfmPathNfInstancesNfInstanceId, path_nf_instance_id);
  uri = nrf_api_root + fmt::format(path_nf_instance_id, nf_instance);
}

//---------------------------------------------------------------------------------------------
std::string sbi_helper::get_nrf_nf_instance_uri(
    const oai::config::sbi_interface& nrf, bool enable_tls,
    const std::string& nf_instance) {
  std::string nrf_api_root        = get_nrf_nfm_api_root(nrf, enable_tls);
  std::string path_nf_instance_id = {};
  get_fmt_format_form(
      sbi_helper::NrfNfmPathNfInstancesNfInstanceId, path_nf_instance_id);
  return nrf_api_root + fmt::format(path_nf_instance_id, nf_instance);
}

//---------------------------------------------------------------------------------------------
void sbi_helper::get_nrf_disc_api_root(
    const nf_addr_t& nrf_addr, std::string& api_root) {
  api_root = nrf_addr.uri_root + sbi_helper::NrfDiscBase + nrf_addr.api_version;
}

//---------------------------------------------------------------------------------------------
std::string sbi_helper::get_nrf_disc_api_root(
    const oai::config::sbi_interface& nrf, bool enable_tls) {
  return nrf.get_url(enable_tls) + sbi_helper::NrfDiscBase +
         nrf.get_api_version();
}

//---------------------------------------------------------------------------------------------
void sbi_helper::get_nrf_disc_search_nf_instances_uri(
    const nf_addr_t& nrf_addr, std::string& uri) {
  std::string api_root = {};
  get_nrf_disc_api_root(nrf_addr, api_root);
  uri = api_root + NrfDiscPathNfInstances;
}

//---------------------------------------------------------------------------------------------
std::string sbi_helper::get_nrf_disc_search_nf_instances_uri(
    const oai::config::sbi_interface& nrf, bool enable_tls) {
  std::string api_root = get_nrf_disc_api_root(nrf, enable_tls);
  return api_root + NrfDiscPathNfInstances;
}

//---------------------------------------------------------------------------------------------
void sbi_helper::get_fmt_format_form(
    const std::string& input_str, std::string& output_str) {
  // First replace request parameters (except the last one) with {}
  std::regex e_parameter("\\:[a-zA-Z0-9]+\\/");
  std::string tmp = std::regex_replace(
      input_str, e_parameter, "{}/", std::regex_constants::match_any);

  // Replace the last request parameter with {}
  std::regex e_last_parameter("\\:[a-zA-Z0-9]+");
  output_str = std::regex_replace(
      tmp, e_last_parameter, "{}", std::regex_constants::match_any);
}

//---------------------------------------------------------------------------------------------
void sbi_helper::parse_query(
    const std::string& query_string,
    std::map<std::string, std::string>& parameters) {
  std::regex param_reg("([^=]*)=([^&]*)&?");

  std::for_each(
      std::sregex_iterator(query_string.begin(), query_string.end(), param_reg),
      std::sregex_iterator(), [&parameters](std::smatch match) {
        parameters.insert(std::pair<std::string, std::string>(
            match[1].str().c_str(), match[2].str().c_str()));
        return;
      });
  return;
}
