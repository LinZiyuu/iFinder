/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udm_sbi_helper.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>
#include <vector>

#include "ProblemDetails.h"
#include "logger.hpp"

namespace oai::udm::api {
//------------------------------------------------------------------------------
void udm_sbi_helper::set_problem_details(
    nlohmann::json& json_data, const std::string& detail) {
  Logger::udm_server().error("%s", detail);
  oai::model::common::ProblemDetails problem_details;
  problem_details.setDetail(detail);
  to_json(json_data, problem_details);
}

//------------------------------------------------------------------------------
std::string
udm_sbi_helper::get_udr_slice_selection_subscription_data_retrieval_uri(
    const std::string& supi, const oai::model::common::PlmnId& plmn_id) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataProvisionedDataAmData,
      fmr_format_str);
  return get_udr_uri_base() +
         fmt::format(fmr_format_str, supi, plmn_id.getMcc() + plmn_id.getMnc());
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_access_and_mobility_subscription_data_uri(
    const std::string& supi, const oai::model::common::PlmnId& plmn_id) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataProvisionedDataAmData,
      fmr_format_str);
  return get_udr_uri_base() +
         fmt::format(fmr_format_str, supi, plmn_id.getMcc() + plmn_id.getMnc());
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_session_management_subscription_data_uri(
    const std::string& supi, const oai::model::common::PlmnId& plmn_id) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataProvisionedDataSmData,
      fmr_format_str);
  return get_udr_uri_base() +
         fmt::format(fmr_format_str, supi, plmn_id.getMcc() + plmn_id.getMnc());
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_smf_selection_subscription_data_uri(
    const std::string& supi, const oai::model::common::PlmnId& plmn_id) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataProvisionedDataSmf,
      fmr_format_str);
  return get_udr_uri_base() +
         fmt::format(fmr_format_str, supi, plmn_id.getMcc() + plmn_id.getMnc());
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_sdm_subscriptions_uri(
    const std::string& supi) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataContextDataSdmSubscriptions,
      fmr_format_str);
  return get_udr_uri_base() + fmt::format(fmr_format_str, supi);
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_authentication_subscription_uri(
    const std::string& supi) {
  std::string udr_path_fmt = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataAuthenticationSubscription,
      udr_path_fmt);
  return get_udr_uri_base() + fmt::format(udr_path_fmt, supi);
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_authentication_status_uri(
    const std::string& supi) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataAuthenticationStatus,
      fmr_format_str);
  return get_udr_uri_base() + fmt::format(fmr_format_str, supi);
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_amf_3gpp_registration_uri(
    const std::string& supi) {
  std::string fmr_format_str = {};
  udm_sbi_helper::get_fmt_format_form(
      udm_sbi_helper::UdrDrPathSubscriptionDataContextDataAmf3gppAccess,
      fmr_format_str);
  return get_udr_uri_base() + fmt::format(fmr_format_str, supi);
}

//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udm_ueau_base() {
  return udm_cfg.sbi.get_ipv4_root() +
         oai::udm::api::udm_sbi_helper::UeAuthenticationServiceBase;
}
//------------------------------------------------------------------------------
std::string udm_sbi_helper::get_udr_uri_base() {
  return udm_cfg.udr_addr.uri_root + udm_sbi_helper::UdrDataRepositoryBase +
         udm_cfg.udr_addr.api_version;
}
}  // namespace oai::udm::api
