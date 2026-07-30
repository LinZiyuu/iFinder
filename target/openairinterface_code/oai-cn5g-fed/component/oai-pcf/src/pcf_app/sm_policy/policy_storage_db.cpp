/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "policy_storage_db.hpp"
#include <string>
#include <sstream>
#include <boost/algorithm/string/predicate.hpp>
#include <mysql_db.hpp>
#include "SupiPolicyDecision.h"
#include "supi_policy_decision.hpp"
#include "dnn_policy_decision.hpp"
#include "slice_policy_decision.hpp"
#include "pcf_config.hpp"

using namespace oai::pcf::app::sm_policy;
using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::pcf::provisioning::model;
using namespace oai::pcf::app;

extern std::unique_ptr<oai::config::pcf::pcf_config> pcf_cfg;
extern std::unique_ptr<database_wrapper_abstraction> db_connector;

policy_storage_db::policy_storage_db() {
  // Use the appropriate DB connector to initialize the connection to the DB
  if (boost::iequals(
          pcf_cfg->get_database_config().get_database_type(), "mysql")) {
    db_connector = std::make_unique<mysql_db>(std::bind(
        &policy_storage_db::notify_subscribers, this, std::placeholders::_1));
  } else {
    Logger::pcf_app().error(
        "PCF currently only supports MySQL for storing policies!");
    exit(-1);
  }

  Logger::pcf_app().startup("Connect to DB...");
  if (!db_connector->connect(MAX_FIRST_CONNECTION_RETRY)) {
    Logger::pcf_app().error("Could not establish the connection to the DB");
    exit(-1);
  }
}

std::shared_ptr<policy_decision> policy_storage_db::find_policy(
    const SmPolicyContextData& context) {
  std::string msg_base = "SM Policy request from SUPI:";
  std::string supi     = context.getSupi();

  try {
    // First, check based on SUPI, then DNN, then Slice, then global default
    // rule.
    try {
      SupiPolicyDecision supiDecision =
          db_connector->getSupiPolicyDecision(supi);

      Logger::pcf_app().debug("%s Decide based on SUPI", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(supiDecision.getPccRuleIds());
      return std::make_shared<supi_policy_decision>(supi, smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find SUPI policy", msg_base, supi);
    }

    try {
      std::string dnn               = context.getDnn();
      DnnPolicyDecision dnnDecision = db_connector->getDnnPolicyDecision(dnn);

      Logger::pcf_app().debug("%s Decide based on DNN", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(dnnDecision.getPccRuleIds());
      return std::make_shared<dnn_policy_decision>(dnn, smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find DNN policy", msg_base, supi);
    }

    try {
      Snssai slice = context.getSliceInfo();
      SlicePolicyDecision sliceDecision =
          db_connector->getSlicePolicyDecision(context.getSliceInfo());

      Logger::pcf_app().debug("%s Decide based on slice", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(sliceDecision.getPccRuleIds());
      return std::make_shared<slice_policy_decision>(slice, smPolicyDecision);

    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find slice policy", msg_base, supi);
    }

    try {
      std::vector<std::string> defaultPccRules =
          db_connector->getDefaultPolicyDecision();

      Logger::pcf_app().debug("%s Decide based on default policy", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(defaultPccRules);
      return std::make_shared<policy_decision>(smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find default policy", msg_base, supi);
      return nullptr;
    }
  } catch (const std::exception& e) {
    Logger::pcf_app().error(
        "%s %s - Error during requesting decisions from DB: %e", msg_base, supi,
        e.what());
    return nullptr;
  }
}

void policy_storage_db::notify_subscribers(
    const std::shared_ptr<policy_decision>& decision) {
  // TODO
  Logger::pcf_app().debug("Not implemented: Notifying subscribers");
}

void policy_storage_db::subscribe_to_decision_change(
    std::function<void(std::shared_ptr<policy_decision>&)> callback) {
  // TODO
  Logger::pcf_app().debug("Not implemented: Subscribing to decision change");
}

void policy_storage_db::insert_supi_decision(
    const std::string& supi,
    const oai::model::pcf::SmPolicyDecision& decision) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting SUPI decision into DB");
}

void policy_storage_db::insert_dnn_decision(
    const std::string& dnn, const oai::model::pcf::SmPolicyDecision& decision) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting DNN decision into DB");
}

void policy_storage_db::insert_slice_decision(
    const oai::model::common::Snssai&,
    const oai::model::pcf::SmPolicyDecision& decision) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting Slice decision into DB");
}

void policy_storage_db::insert_associations(
    const oai::model::pcf::SmPolicyContextData& context,
    const std::string& association_id) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting associations into DB");
}

void policy_storage_db::insert_ip_association(
    const std::string& dnn, const std::string& association_id) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting IP association into DB");
}

void policy_storage_db::insert_supi_association(
    const std::string& supi, const std::string& association_id) {
  // TODO implement
  Logger::pcf_app().debug(
      "Not implemented: Inserting SUPI association into DB");
}

void policy_storage_db::insert_dnn_association(
    const std::string& dnn, const std::string& association_id) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Inserting DNN association into DB");
}

std::shared_ptr<std::string> policy_storage_db::find_association(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn) {
  // TODO implement
  Logger::pcf_app().debug("Not implemented: Finding association in DB");
  return NULL;
}