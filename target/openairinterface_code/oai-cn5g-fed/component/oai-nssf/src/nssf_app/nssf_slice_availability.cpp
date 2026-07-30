/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nssf_slice_availability.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>

#include "conversions.hpp"
#include "logger.hpp"
#include "nssf.h"
#include "nssf_config.hpp"

using namespace nssf;
using namespace oai::config::nssf;
using namespace oai::model::common;

extern nssf_slice_avail* nssf_slice_avail_inst;
extern std::unique_ptr<oai::config::nssf::nssf_config> nssf_cfg;
//------------------------------------------------------------------------------
bool nssf_slice_avail::amf_set_present(
    const std::string& target_amf_set, amf_info_t& amf_info) {
  for (auto amf_info_it : nssf_cfg->nssf_amf_info.amf_info_list) {
    if (!amf_info_it.target_amf_set.compare(target_amf_set)) {
      amf_info = amf_info_it;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool nssf_slice_avail::handle_create_nssai_availability(
    const std::string& nfId,
    const oai::nssf_server::model::NssaiAvailabilityInfo& nssaiAvailInfo,
    oai::nssf_server::model::AuthorizedNssaiAvailabilityInfo& auth_info,
    int& http_code, const uint8_t http_version,
    const oai::model::common::ProblemDetails& problem_details) {
  if (nssaiAvailInfo.amfSetIdIsSet()) {
    std::string amf_set = nssaiAvailInfo.getAmfSetId();
    Logger::nssf_app().info(
        "NS Availability: Create NSSAIs availability info for AMF "
        "(HTTP_VERSION %d)",
        http_version);
    // ToDo:- Check if SupportedSnssaiList & Tai in valid in plmn

    // Check if target_amf_set is present in nssf slice config
    if (!amf_set.empty()) {
      amf_info_t amf_info;
      if (amf_set_present(amf_set, amf_info)) {
        Logger::nssf_app().debug(
            "target_amf_set matched -> %s", amf_info.target_amf_set.c_str());
        bool update_done = false;
        for (auto amf : amf_info.amf_List) {
          if (!amf.first.compare(nfId)) {
            Logger::nssf_app().info(
                "Replacing nssaiAvailInfo for existing AMF");
            amf.second.clear();
            amf.second  = nssaiAvailInfo.getSupportedNssaiAvailabilityData();
            update_done = true;
            http_code   = oai::common::sbi::http_status_code::NO_CONTENT;
            break;
          }
        }
        if (!update_done) {
          Logger::nssf_app().info("Creating nssaiAvailInfo for new AMF");
          amf_info.amf_List.emplace_back(
              nfId.c_str(), nssaiAvailInfo.getSupportedNssaiAvailabilityData());
          http_code = oai::common::sbi::http_status_code::NO_CONTENT;
        }
      } else {
        Logger::nssf_app().warn("target_amf_set not matched");
        http_code = oai::common::sbi::http_status_code::SERVICE_UNAVAILABLE;
        return false;
      }
    }
  } else {
    Logger::nssf_app().warn("Optional field target_amf_set not provided");
    // ToDo:- Select first target-amf_set based on tai
    // amf_info_t new_amf_info;
    http_code = oai::common::sbi::http_status_code::SERVICE_UNAVAILABLE;
    return false;
  }

  return true;
}
//------------------------------------------------------------------------------
bool nssf_slice_avail::handle_update_nssai_availability(
    const std::string& nfId, const std::vector<PatchItem>& patchItem,
    int& http_code, const uint8_t http_version,
    const ProblemDetails& problem_details) {
  // ToDo
  return false;
}
//------------------------------------------------------------------------------
bool nssf_slice_avail::handle_remove_nssai_availability(
    const std::string& nfId, int& http_code, const uint8_t http_version,
    const ProblemDetails& problem_details) {
  // ToDo
  return false;
}
//------------------------------------------------------------------------------
// Handle NSSF NSSAI Availability - Subscription ID (Collection/Document)
bool nssf_slice_avail::handle_create_subscription_nssai_availability(
    const oai::nssf_server::model::NssfEventSubscriptionCreateData&
        subscriptionData,
    int& http_code, const uint8_t http_version,
    const ProblemDetails& problem_details) {
  // ToDo
  return false;
}
//------------------------------------------------------------------------------
bool nssf_slice_avail::handle_update_subscription_nssai_availability(
    const oai::nssf_server::model::NssfEventSubscriptionCreateData&
        subscriptionData,
    int& http_code, const uint8_t http_version,
    const ProblemDetails& problem_details) {
  // ToDo
  return false;
}
//------------------------------------------------------------------------------
bool nssf_slice_avail::handle_remove_subscription_nssai_availability(
    const std::string& subscriptionId, int& http_code,
    const uint8_t http_version, const ProblemDetails& problem_details) {
  // ToDo
  return false;
}
//------------------------------------------------------------------------------
nssf_slice_avail::~nssf_slice_avail() {
  Logger::nssf_app().debug("Delete NSSF_SLICE_AVAIL instance...");
}
