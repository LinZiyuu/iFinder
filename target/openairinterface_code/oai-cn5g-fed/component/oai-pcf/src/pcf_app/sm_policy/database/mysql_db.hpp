/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef MYSQL_DB_HPP
#define MYSQL_DB_HPP

#include <mysql/mysql.h>
#include <shared_mutex>
#include <odb/database.hxx>
#include <odb/mysql/exceptions.hxx>
#include <odb/mysql/database.hxx>
#include <odb/transaction.hxx>

#include "database_wrapper.hpp"
#include "database_wrapper_abstraction.hpp"
#include "pcf_event.hpp"
#include "Snssai.h"
#include "SupiPolicyDecision.h"
#include "SupiPolicyDecision-odb.hxx"
#include "DnnPolicyDecision.h"
#include "DnnPolicyDecision-odb.hxx"
#include "SlicePolicyDecision.h"
#include "SlicePolicyDecision-odb.hxx"
#include "QosData.h"
#include "QosData-odb.hxx"
#include "TrafficControlData.h"
#include "TrafficControlDataODB.h"
#include "TrafficControlDataODB-odb.hxx"
#include "PccRule.h"
#include "PccRuleODB.h"
#include "PccRuleODB-odb.hxx"
#include "../policy_storage_db.hpp"

namespace oai::pcf::app {

class mysql_db : public database_wrapper<mysql_db> {
 public:
  mysql_db(
      std::function<void(const std::shared_ptr<sm_policy::policy_decision>&)>
          notify_callback);

  virtual ~mysql_db();

  bool connect(uint32_t num_retries);

  /**
   * Set and Get DefaultPolicyDecision
   */

  bool setDefaultPolicyDecision(std::vector<std::string> rules);

  std::vector<std::string> getDefaultPolicyDecision();

  /**
   * SupiPolicyDecision CRUD functions
   */

  bool createSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision);

  oai::pcf::provisioning::model::SupiPolicyDecision getSupiPolicyDecision(
      const std::string& supi);

  bool updateSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision);

  bool deleteSupiPolicyDecision(const std::string& supi);

  std::vector<oai::pcf::provisioning::model::SupiPolicyDecision>
  getAllSupiPolicyDecisions();

  /**
   * DnnPolicyDecision CRUD functions
   */

  bool createDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  oai::pcf::provisioning::model::DnnPolicyDecision getDnnPolicyDecision(
      const std::string& dnn);

  bool updateDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  bool deleteDnnPolicyDecision(const std::string& dnn);

  std::vector<oai::pcf::provisioning::model::DnnPolicyDecision>
  getAllDnnPolicyDecisions();

  /**
   * SlicePolicyDecision CRUD functions
   */

  bool createSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision);

  oai::pcf::provisioning::model::SlicePolicyDecision getSlicePolicyDecision(
      const oai::model::common::Snssai& slice);

  bool updateSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision);

  bool deleteSlicePolicyDecision(const oai::model::common::Snssai& slice);

  std::vector<oai::pcf::provisioning::model::SlicePolicyDecision>
  getAllSlicePolicyDecisions();

  /**
   * QosData CRUD functions
   */

  bool createQosData(const oai::model::pcf::QosData& qosData);

  oai::model::pcf::QosData getQosData(const std::string& qosId);

  bool updateQosData(const oai::model::pcf::QosData& qosData);

  bool deleteQosData(const std::string& qosId);

  std::vector<oai::model::pcf::QosData> getAllQosData();

  /**
   * TrafficControlData CRUD functions
   */

  bool createTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData);

  oai::model::pcf::TrafficControlData getTrafficControlData(
      const std::string& tcId);

  bool updateTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData);

  bool deleteTrafficControlData(const std::string& tcId);

  std::vector<oai::model::pcf::TrafficControlData> getAllTrafficControlData();

  /**
   * PccRule CRUD functions
   */

  bool createPccRule(const oai::model::pcf::PccRule& pccRule);

  oai::model::pcf::PccRule getPccRule(const std::string& pccRuleId);

  bool updatePccRule(const oai::model::pcf::PccRule& pccRule);

  bool deletePccRule(const std::string& pccRuleId);

  std::vector<oai::model::pcf::PccRule> getAllPccRules();

  oai::model::pcf::SmPolicyDecision getSmPolicyDecision(
      const std::vector<std::string>& pccRuleIds);

 private:
  std::shared_ptr<odb::database> db;
  std::function<void(const std::shared_ptr<sm_policy::policy_decision>&)>
      notify_func;

  void check_db_connection() const {
    if (!db) {
      Logger::pcf_db().error("Database connection is not established.");
      throw std::runtime_error("Database connection is not established.");
    }
  }
};
}  // namespace oai::pcf::app

#endif  // MYSQL_DB_HPP
