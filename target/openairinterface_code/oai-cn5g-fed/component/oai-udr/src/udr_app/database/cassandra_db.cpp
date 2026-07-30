/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "cassandra_db.hpp"

#include "AuthenticationSubscription.h"
#include "logger.hpp"
#include "udr_config.hpp"

using namespace oai::udr::app;
using namespace oai::udr::model;
using namespace oai::udr::config;
extern udr_config udr_cfg;

//------------------------------------------------------------------------------
cassandra_db::cassandra_db() : database_wrapper<cassandra_db>() {}

//------------------------------------------------------------------------------
cassandra_db::~cassandra_db() {}

//------------------------------------------------------------------------------
bool cassandra_db::initialize() {
  Logger::udr_app().debug("Initialize CassandraDB");
  Logger::udr_app().debug("CassandraDB is not supported!");
  return false;
}

//------------------------------------------------------------------------------
bool cassandra_db::connect(uint32_t num_retries) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::close_connection() {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::insert_authentication_subscription(
    const std::string& id,
    const oai::udr::model::AuthenticationSubscription&
        authentication_subscription,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::delete_authentication_subscription(
    const std::string& id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_authentication_subscription(
    const std::string& id, nlohmann::json& json_data) {
  Logger::udr_app().debug("CassandraDB is not supported!");
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::update_authentication_subscription(
    const std::string& id,
    const std::vector<oai::model::common::PatchItem>& patchItem,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_am_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::create_amf_context_3gpp(
    const std::string& ue_id,
    oai::udr::model::Amf3GppAccessRegistration& amf3GppAccessRegistration,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_amf_context_3gpp(
    const std::string& ue_id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::cassandra_db::insert_authentication_status(
    const std::string& ue_id, const oai::udr::model::AuthEvent& authEvent,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::cassandra_db::delete_authentication_status(
    const std::string& ue_id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::cassandra_db::query_authentication_status(
    const std::string& ue_id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::cassandra_db::query_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::cassandra_db::delete_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::update_sdm_subscription(
    const std::string& ue_id, const std::string& subs_id,
    oai::udr::model::SdmSubscription& sdmSubscription,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::create_sdm_subscriptions(
    const std::string& ue_id, oai::udr::model::SdmSubscription& sdmSubscription,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_sdm_subscriptions(
    const std::string& ue_id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_sm_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data, const std::optional<oai::model::common::Snssai>&,
    const std::optional<std::string>& dnn) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_sm_data(nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::create_sm_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    oai::udr::model::SessionManagementSubscriptionData& sm_subscription,
    nlohmann::json& json_data, uint32_t& resource_id) {
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::update_sm_data(
    const std::string& ueId, const std::string& servingPlmnId,
    oai::udr::model::SessionManagementSubscriptionData& subscriptionData,
    nlohmann::json& json_data, uint32_t& resource_id) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::delete_sm_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    const std::optional<oai::model::common::Snssai>& snssai) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::insert_smf_context_non_3gpp(
    const std::string& ue_id, const int32_t& pdu_session_id,
    const oai::udr::model::SmfRegistration& smfRegistration,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::delete_smf_context(
    const std::string& ue_id, const int32_t& pdu_session_id,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_smf_registration(
    const std::string& ue_id, const int32_t& pdu_session_id,
    nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_smf_reg_list(
    const std::string& ue_id, nlohmann::json& json_data) {
  return true;
}

//------------------------------------------------------------------------------
bool cassandra_db::query_smf_select_data(
    const std::string& ue_id, const std::string& serving_plmn_id,
    nlohmann::json& json_data) {
  return true;
}
