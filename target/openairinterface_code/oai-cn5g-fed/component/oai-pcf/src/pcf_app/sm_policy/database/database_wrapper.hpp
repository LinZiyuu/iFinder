/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef DATABASE_WRAPPER_HPP
#define DATABASE_WRAPPER_HPP

#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

#define MAX_FIRST_CONNECTION_RETRY 100

namespace oai::pcf::app {

class NotFoundException : public std::exception {
 private:
  std::string message;

 public:
  NotFoundException(const std::string& msg) : message("NotFound: " + msg) {}

  const char* what() const noexcept override { return message.c_str(); }
};

class AlreadyExistException : public std::exception {
 private:
  std::string message;

 public:
  AlreadyExistException(const std::string& msg)
      : message("AlreadyExist: " + msg) {}

  const char* what() const noexcept override { return message.c_str(); }
};

template<class DerivedT>
class database_wrapper : public database_wrapper_abstraction {
 public:
  database_wrapper(){};

  virtual ~database_wrapper(){};

  bool connect(uint32_t num_retries) override {
    Logger::pcf_app().debug(
        "Establish the connection to the DB (from database_wrapper)");
    auto derived = static_cast<DerivedT*>(this);
    return derived->connect(num_retries);
  }

  bool setDefaultPolicyDecision(std::vector<std::string> rules) override {
    Logger::pcf_app().debug("Set default rules");
    auto derived = static_cast<DerivedT*>(this);
    return derived->setDefaultPolicyDecision(rules);
  }

  std::vector<std::string> getDefaultPolicyDecision() override {
    Logger::pcf_app().debug("get default rules");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getDefaultPolicyDecision();
  }

  bool createSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision) override {
    Logger::pcf_app().debug("Create supiPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createSupiPolicyDecision(supiPolicyDecision);
  }

  oai::pcf::provisioning::model::SupiPolicyDecision getSupiPolicyDecision(
      const std::string& supi) override {
    Logger::pcf_app().debug("Get supiPolicyDecision by supi");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getSupiPolicyDecision(supi);
  }

  bool updateSupiPolicyDecision(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision) override {
    Logger::pcf_app().debug("Update supiPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updateSupiPolicyDecision(supiPolicyDecision);
  }

  bool deleteSupiPolicyDecision(const std::string& supi) override {
    Logger::pcf_app().debug("Delete supiPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deleteSupiPolicyDecision(supi);
  }

  std::vector<oai::pcf::provisioning::model::SupiPolicyDecision>
  getAllSupiPolicyDecisions() override {
    Logger::pcf_app().debug("Get all supiPolicyDecisions");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllSupiPolicyDecisions();
  }

  bool createDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision& dnnPolicyDecision)
      override {
    Logger::pcf_app().debug("Create dnnPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createDnnPolicyDecision(dnnPolicyDecision);
  }

  oai::pcf::provisioning::model::DnnPolicyDecision getDnnPolicyDecision(
      const std::string& dnn) override {
    Logger::pcf_app().debug("Get dnnPolicyDecision by supi");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getDnnPolicyDecision(dnn);
  }

  bool updateDnnPolicyDecision(
      const oai::pcf::provisioning::model::DnnPolicyDecision& dnnPolicyDecision)
      override {
    Logger::pcf_app().debug("Update dnnPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updateDnnPolicyDecision(dnnPolicyDecision);
  }

  bool deleteDnnPolicyDecision(const std::string& dnn) override {
    Logger::pcf_app().debug("Delete dnnPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deleteDnnPolicyDecision(dnn);
  }

  std::vector<oai::pcf::provisioning::model::DnnPolicyDecision>
  getAllDnnPolicyDecisions() override {
    Logger::pcf_app().debug("Get all dnnPolicyDecisions");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllDnnPolicyDecisions();
  }

  bool createSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision) override {
    Logger::pcf_app().debug("Create slicePolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createSlicePolicyDecision(slicePolicyDecision);
  }

  oai::pcf::provisioning::model::SlicePolicyDecision getSlicePolicyDecision(
      const oai::model::common::Snssai& slice) override {
    Logger::pcf_app().debug("Get slicePolicyDecision by slice");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getSlicePolicyDecision(slice);
  }

  bool updateSlicePolicyDecision(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision) override {
    Logger::pcf_app().debug("Update slicePolicyDecision by slice");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updateSlicePolicyDecision(slicePolicyDecision);
  }

  bool deleteSlicePolicyDecision(
      const oai::model::common::Snssai& slice) override {
    Logger::pcf_app().debug("Delete slicePolicyDecision by slice");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deleteSlicePolicyDecision(slice);
  }

  std::vector<oai::pcf::provisioning::model::SlicePolicyDecision>
  getAllSlicePolicyDecisions() override {
    Logger::pcf_app().debug("Get all slicePolicyDecisions");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllSlicePolicyDecisions();
  }

  bool createQosData(const oai::model::pcf::QosData& qosData) override {
    Logger::pcf_app().debug("Create qosData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createQosData(qosData);
  }

  oai::model::pcf::QosData getQosData(const std::string& qosId) override {
    Logger::pcf_app().debug("Get qosData by qosId");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getQosData(qosId);
  }

  bool updateQosData(const oai::model::pcf::QosData& qosData) override {
    Logger::pcf_app().debug("Update qosData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updateQosData(qosData);
  }

  bool deleteQosData(const std::string& qosId) override {
    Logger::pcf_app().debug("Delete qosData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deleteQosData(qosId);
  }

  std::vector<oai::model::pcf::QosData> getAllQosData() override {
    Logger::pcf_app().debug("Get all qosData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllQosData();
  }

  bool createTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData) override {
    Logger::pcf_app().debug("Create TrafficControlData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createTrafficControlData(trafficControlData);
  }

  oai::model::pcf::TrafficControlData getTrafficControlData(
      const std::string& tcId) override {
    Logger::pcf_app().debug("Get TrafficControlData by tcId");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getTrafficControlData(tcId);
  }

  bool updateTrafficControlData(
      const oai::model::pcf::TrafficControlData& trafficControlData) override {
    Logger::pcf_app().debug("Update trafficControlData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updateTrafficControlData(trafficControlData);
  }

  bool deleteTrafficControlData(const std::string& tcId) override {
    Logger::pcf_app().debug("Delete trafficControlData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deleteTrafficControlData(tcId);
  }

  std::vector<oai::model::pcf::TrafficControlData> getAllTrafficControlData()
      override {
    Logger::pcf_app().debug("Get all trafficControlData");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllTrafficControlData();
  }

  bool createPccRule(const oai::model::pcf::PccRule& pccRule) override {
    Logger::pcf_app().debug("Create PccRule");
    auto derived = static_cast<DerivedT*>(this);
    return derived->createPccRule(pccRule);
  }

  oai::model::pcf::PccRule getPccRule(const std::string& pccRuleId) override {
    Logger::pcf_app().debug("Get PccRule by pccRuleId");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getPccRule(pccRuleId);
  }

  bool updatePccRule(const oai::model::pcf::PccRule& pccRule) override {
    Logger::pcf_app().debug("Update pccRule");
    auto derived = static_cast<DerivedT*>(this);
    return derived->updatePccRule(pccRule);
  }

  bool deletePccRule(const std::string& pccRuleId) override {
    Logger::pcf_app().debug("Delete pccRule");
    auto derived = static_cast<DerivedT*>(this);
    return derived->deletePccRule(pccRuleId);
  }

  std::vector<oai::model::pcf::PccRule> getAllPccRules() override {
    Logger::pcf_app().debug("Get all pccRules");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getAllPccRules();
  }

  virtual oai::model::pcf::SmPolicyDecision getSmPolicyDecision(
      const std::vector<std::string>& pccRuleIds) override {
    Logger::pcf_app().debug("get SmPolicyDecision");
    auto derived = static_cast<DerivedT*>(this);
    return derived->getSmPolicyDecision(pccRuleIds);
  }
};
}  // namespace oai::pcf::app
#endif  // DATABASE_WRAPPER_HPP