/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DATABASE_WRAPPER_ABSTRACTION_HPP
#define DATABASE_WRAPPER_ABSTRACTION_HPP

#include "logger.hpp"
#include "SupiPolicyDecision.h"
#include "DnnPolicyDecision.h"
#include "SmPolicyDecision.h"
#include "SlicePolicyDecision.h"
#include "QosData.h"
#include "TrafficControlData.h"
#include "PccRule.h"

namespace oai::pcf::app {
class database_wrapper_abstraction {
 public:
  database_wrapper_abstraction(){};

  virtual ~database_wrapper_abstraction(){};

  /*
   * Establish the connection between PCF and the DB
   * @param [uint32_t] num_retries: Number of retires
   * @return true if successful, otherwise return false
   */
  virtual bool connect(uint32_t num_retries) = 0;

  virtual bool setDefaultPolicyDecision(std::vector<std::string> rules) = 0;

  virtual std::vector<std::string> getDefaultPolicyDecision() = 0;

  virtual bool createSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision) = 0;

  virtual oai::pcf::provisioning::model::SupiPolicyDecision
  getSupiPolicyDecision(const std::string& supi) = 0;

  virtual bool updateSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision) = 0;

  virtual bool deleteSupiPolicyDecision(const std::string& supi) = 0;

  virtual std::vector<oai::pcf::provisioning::model::SupiPolicyDecision>
  getAllSupiPolicyDecisions() = 0;

  virtual bool createDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision) = 0;

  virtual oai::pcf::provisioning::model::DnnPolicyDecision getDnnPolicyDecision(
      const std::string& dnn) = 0;

  virtual bool updateDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision) = 0;

  virtual bool deleteDnnPolicyDecision(const std::string& dnn) = 0;

  virtual std::vector<oai::pcf::provisioning::model::DnnPolicyDecision>
  getAllDnnPolicyDecisions() = 0;

  virtual bool createSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision) = 0;

  virtual oai::pcf::provisioning::model::SlicePolicyDecision
  getSlicePolicyDecision(const oai::model::common::Snssai& slice) = 0;

  virtual bool updateSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision) = 0;

  virtual bool deleteSlicePolicyDecision(
      const oai::model::common::Snssai& slice) = 0;

  virtual std::vector<oai::pcf::provisioning::model::SlicePolicyDecision>
  getAllSlicePolicyDecisions() = 0;

  virtual bool createQosData(const oai::model::pcf::QosData& qosData) = 0;

  virtual oai::model::pcf::QosData getQosData(const std::string& qosId) = 0;

  virtual bool updateQosData(const oai::model::pcf::QosData& qosData) = 0;

  virtual bool deleteQosData(const std::string& qosId) = 0;

  virtual std::vector<oai::model::pcf::QosData> getAllQosData() = 0;

  virtual bool createTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData) = 0;

  virtual oai::model::pcf::TrafficControlData getTrafficControlData(
      const std::string& tcId) = 0;

  virtual bool updateTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData) = 0;

  virtual bool deleteTrafficControlData(const std::string& tcId) = 0;

  virtual std::vector<oai::model::pcf::TrafficControlData>
  getAllTrafficControlData() = 0;

  virtual bool createPccRule(const oai::model::pcf::PccRule& pccRule) = 0;

  virtual oai::model::pcf::PccRule getPccRule(const std::string& pccRuleId) = 0;

  virtual bool updatePccRule(const oai::model::pcf::PccRule& pccRule) = 0;

  virtual bool deletePccRule(const std::string& pccRuleId) = 0;

  virtual std::vector<oai::model::pcf::PccRule> getAllPccRules() = 0;

  virtual oai::model::pcf::SmPolicyDecision getSmPolicyDecision(
      const std::vector<std::string>& pccRuleIds) = 0;
};

}  // namespace oai::pcf::app

#endif  // DATABASE_WRAPPER_ABSTRACTION_HPP
