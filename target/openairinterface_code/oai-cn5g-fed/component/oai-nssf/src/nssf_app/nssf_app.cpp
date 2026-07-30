/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nssf_app.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>

#include "conversions.hpp"
#include "logger.hpp"
#include "nssf.h"
#include "nssf_config.hpp"

using namespace nssf;
using namespace oai::model::common;

extern nssf_app* nssf_app_inst;

void nssf_app_task(void*);

//------------------------------------------------------------------------------
void nssf_app::handle_slice_info_for_registration(
    const SliceInfoForRegistration& slice_info, const Tai& tai,
    const PlmnId& home_plmnid, const std::string& features, int& http_code,
    const uint8_t http_version, ProblemDetails& problem_details,
    AuthorizedNetworkSliceInfo& auth_slice_info) {
  if (nssf_nss.handle_slice_info_for_registration(
          slice_info, tai, home_plmnid, features, http_code, http_version,
          problem_details, auth_slice_info)) {
    Logger::nssf_app().info(
        "NS Selection: Authorized Network Slice Info Returned !!!");
    Logger::nssf_app().info(
        "//---------------------------------------------------------");
  } else {
    if (http_code == oai::common::sbi::http_status_code::FORBIDDEN) {
      problem_details.setTitle("UNSUPPORTED_RESOURCE");
      problem_details.setStatus(oai::common::sbi::http_status_code::FORBIDDEN);
      problem_details.setDetail(
          "S-NSSAI in Requested NSSAI is not supported in PLMN");
      problem_details.setCause("SNSSAI_NOT_SUPPORTED");
      Logger::nssf_app().error("NS Selection failure !!!");
    }
  }
  return;
}

//------------------------------------------------------------------------------
void nssf_app::handle_slice_info_for_pdu_session(
    const SliceInfoForPDUSession& slice_info, const Tai& tai,
    const PlmnId& home_plmnid, const std::string& features, int& http_code,
    const uint8_t http_version, ProblemDetails& problem_details,
    AuthorizedNetworkSliceInfo& auth_slice_info) {
  if (nssf_nss.handle_slice_info_for_pdu_session(
          slice_info, tai, home_plmnid, features, http_code, http_version,
          problem_details, auth_slice_info)) {
    Logger::nssf_app().info(
        "NS Selection: Authorized Network Slice Info Returned !!!");
    Logger::nssf_app().info(
        "//---------------------------------------------------------");
  } else {
    if (http_code == oai::common::sbi::http_status_code::FORBIDDEN) {
      problem_details.setTitle("UNSUPPORTED_RESOURCE");
      problem_details.setStatus(oai::common::sbi::http_status_code::FORBIDDEN);
      problem_details.setDetail(
          "S-NSSAI in Requested NSSAI is not supported in PLMN");
      problem_details.setCause("SNSSAI_NOT_SUPPORTED");
      Logger::nssf_app().error("NS Selection failure !!!");
    }
  }
  return;
}

//------------------------------------------------------------------------------
void nssf_app::handle_slice_info_for_ue_cu(
    const SliceInfoForUEConfigurationUpdate& slice_info, const Tai& tai,
    const PlmnId& home_plmnid, const std::string& features, int& http_code,
    const uint8_t http_version, ProblemDetails& problem_details) {
  // ToDo:
}
//------------------------------------------------------------------------------
void nssf_app::handle_create_nssai_availability(
    const std::string& nfId, const NssaiAvailabilityInfo& nssaiAvailInfo,
    AuthorizedNssaiAvailabilityInfo& auth_info, int& http_code,
    const uint8_t http_version, ProblemDetails& problem_details) {
  if (nssf_nsa.handle_create_nssai_availability(
          nfId, nssaiAvailInfo, auth_info, http_code, http_version,
          problem_details)) {
    Logger::nssf_app().info(
        "NSSAI_AVAIL: NssaiAvailabilityInfo Successfully Created/Replaced !!!");
    Logger::nssf_app().info(
        "//---------------------------------------------------------");
  } else {
    if (http_code == oai::common::sbi::http_status_code::FORBIDDEN) {
      problem_details.setTitle("UNSUPPORTED_RESOURCE");
      problem_details.setStatus(oai::common::sbi::http_status_code::FORBIDDEN);
      problem_details.setDetail("NSSAI Availability");
      problem_details.setCause("SNSSAI_NOT_SUPPORTED");
      Logger::nssf_app().error("NSSAI Availability failure !!!");
    }
  }
  return;
}

//------------------------------------------------------------------------------
nssf_app::~nssf_app() {
  Logger::nssf_app().debug("Delete NSSF_APP instance...");
}
