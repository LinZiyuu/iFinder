/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "TrafficControlData.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class traffic_control_data_handler : public handler_base {
 public:
  /**
   *
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_get();

  /**
   *
   * @param trafficControlData
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_post(
      const oai::model::pcf::TrafficControlData& trafficControlData);

  /**
   *
   * @param tcId
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_delete(
      const std::string& tcId);

  /**
   *
   * @param tcId
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_get(
      const std::string& tcId);

  /**
   *
   * @param tcId
   * @param trafficControlData
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_put(
      const std::string& tcId,
      const oai::model::pcf::TrafficControlData& trafficControlData);
};
}  // namespace oai::pcf::provisioning::api
