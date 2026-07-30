/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_app.hpp"
#include "pcf_nrf.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "SupiPolicyDecision.h"
#include "QosData.h"

#include <stdexcept>

using namespace oai::pcf::app;
using namespace oai::config::pcf;
using namespace oai::model::pcf;

extern std::unique_ptr<pcf_config> pcf_cfg;
extern std::unique_ptr<database_wrapper_abstraction> db_connector;

//------------------------------------------------------------------------------
pcf_app::pcf_app(pcf_event& ev) : m_event_sub(ev) {
  Logger::pcf_app().startup("Starting...");

  if (pcf_cfg->use_db_policy_storage() &&
      pcf_cfg->get_database_config().is_set()) {
    m_policy_storage = std::make_shared<sm_policy::policy_storage_db>();

  } else {
    if (pcf_cfg->use_db_policy_storage()) {
      Logger::pcf_app().warn(
          "DB policy storage activated, bot no DB configured!");
    }
    Logger::pcf_app().startup("Reading local Policy configuration...");
    m_policy_storage = std::make_shared<sm_policy::policy_storage_yaml>();

    m_provisioning_file = std::make_shared<sm_policy::policy_provisioning_file>(
        std::static_pointer_cast<sm_policy::policy_storage_yaml>(
            m_policy_storage));

    if (!m_provisioning_file->read_all_policy_files()) {
      Logger::pcf_app().error(
          "Cannot read policy configuration from file. Exiting");
      exit(-1);
    }
  }

  // Register to NRF
  if (pcf_cfg->register_nrf()) {
    m_pcf_nrf_inst = std::make_unique<pcf_nrf>(ev);
    m_pcf_nrf_inst->register_to_nrf();
    Logger::pcf_app().info("NRF TASK Created ");
  }

  m_pcf_smpc_service = std::make_shared<pcf_smpc>(m_policy_storage, ev);
  m_pcf_policy_authorization_service =
      std::make_shared<pcf_policy_authorization>(ev);
}

//------------------------------------------------------------------------------
pcf_app::~pcf_app() {
  Logger::pcf_app().debug("Delete PCF_APP instance...");
}

std::shared_ptr<pcf_smpc> pcf_app::get_pcf_smpc_service() {
  return m_pcf_smpc_service;
}

std::shared_ptr<pcf_policy_authorization>
pcf_app::get_pcf_policy_authorization_service() {
  return m_pcf_policy_authorization_service;
}

void pcf_app::stop() {
  if (m_pcf_nrf_inst) {
    m_pcf_nrf_inst->deregister_to_nrf();
  }
}