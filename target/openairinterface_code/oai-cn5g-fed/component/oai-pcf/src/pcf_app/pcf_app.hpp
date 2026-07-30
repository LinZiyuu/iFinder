/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <boost/atomic.hpp>
#include <string>

#include "3gpp_29.500.h"
#include "pcf_profile.hpp"
#include "pcf_event.hpp"
#include "PatchItem.h"
#include "pcf_sm_policy_control.hpp"
#include "sm_policy/policy_storage.hpp"
#include "sm_policy/policy_storage_db.hpp"
#include "sm_policy/policy_storage_yaml.hpp"
#include "sm_policy/policy_provisioning_file.hpp"
#include "pcf_nrf.hpp"
#include "pcf_policy_authorization.hpp"
#include "sm_policy/database/database_wrapper.hpp"
#include "sm_policy/database/mysql_db.hpp"

namespace oai::pcf::app {

class pcf_app {
 public:
  explicit pcf_app(pcf_event& ev);
  pcf_app(pcf_app const&) = delete;
  void operator=(pcf_app const&) = delete;

  virtual ~pcf_app();

  std::shared_ptr<pcf_smpc> get_pcf_smpc_service();
  std::shared_ptr<pcf_policy_authorization>
  get_pcf_policy_authorization_service();

  /**
   * Stop all the ongoing processes and procedures of the PCF APP layer,
   * deregisters at NRF
   */
  void stop();

 private:
  pcf_profile m_nf_instance_profile;  // PCF profile
  std::string m_pcf_instance_id;      // PCF instance id
  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_task_connection;

  std::shared_ptr<pcf_smpc> m_pcf_smpc_service;
  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;
  std::unique_ptr<oai::pcf::app::pcf_nrf> m_pcf_nrf_inst;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_provisioning_file>
      m_provisioning_file;

  std::shared_ptr<pcf_policy_authorization> m_pcf_policy_authorization_service;
};
}  // namespace oai::pcf::app
