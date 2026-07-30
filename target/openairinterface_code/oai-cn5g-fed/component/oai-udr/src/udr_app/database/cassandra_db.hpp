/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef CASSANDRA_DB_HPP
#define CASSANDRA_DB_HPP

#include "database_wrapper.hpp"

namespace oai::udr::app {

class cassandra_db : public database_wrapper<cassandra_db> {
 public:
  cassandra_db();
  virtual ~cassandra_db();

  bool initialize();
  bool connect(uint32_t num_retries);
  bool close_connection();

  bool insert_authentication_subscription(
      const std::string& id,
      const oai::udr::model::AuthenticationSubscription&
          authentication_subscription,
      nlohmann::json& json_data);

  bool delete_authentication_subscription(
      const std::string& id, nlohmann::json& json_data);

  bool query_authentication_subscription(
      const std::string& id, nlohmann::json& json_data);

  bool update_authentication_subscription(
      const std::string& id,
      const std::vector<oai::model::common::PatchItem>& patchItem,
      nlohmann::json& json_data);

  bool query_am_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& json_data);

  bool create_amf_context_3gpp(
      const std::string& ue_id,
      oai::udr::model::Amf3GppAccessRegistration& amf3GppAccessRegistration,
      nlohmann::json& json_data);

  bool query_amf_context_3gpp(
      const std::string& ue_id, nlohmann::json& json_data);

  bool insert_authentication_status(
      const std::string& ue_id, const oai::udr::model::AuthEvent& authEvent,
      nlohmann::json& json_data);

  bool delete_authentication_status(
      const std::string& ue_id, nlohmann::json& json_data);

  bool query_authentication_status(
      const std::string& ue_id, nlohmann::json& json_data);

  bool query_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      nlohmann::json& json_data);

  bool delete_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      nlohmann::json& json_data);

  bool update_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      oai::udr::model::SdmSubscription& sdmSubscription,
      nlohmann::json& json_data);

  bool create_sdm_subscriptions(
      const std::string& ue_id,
      oai::udr::model::SdmSubscription& sdmSubscription,
      nlohmann::json& json_data);

  bool query_sdm_subscriptions(
      const std::string& ue_id, nlohmann::json& json_data);

  bool query_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& json_data,
      const std::optional<oai::model::common::Snssai>& snssai,
      const std::optional<std::string>& dnn);

  bool create_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      oai::udr::model::SessionManagementSubscriptionData& sm_subscription,
      nlohmann::json& json_data, uint32_t& resource_id);

  bool update_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      oai::udr::model::SessionManagementSubscriptionData& subscriptionData,
      nlohmann::json& json_data, uint32_t& resource_id);

  bool delete_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      const std::optional<oai::model::common::Snssai>& snssai);

  bool query_sm_data(nlohmann::json& json_data);

  bool insert_smf_context_non_3gpp(
      const std::string& ue_id, const int32_t& pdu_session_id,
      const oai::udr::model::SmfRegistration& smfRegistration,
      nlohmann::json& json_data);

  bool delete_smf_context(
      const std::string& ue_id, const int32_t& pdu_session_id,
      nlohmann::json& json_data);

  bool query_smf_registration(
      const std::string& ue_id, const int32_t& pdu_session_id,
      nlohmann::json& json_data);

  bool query_smf_reg_list(const std::string& ue_id, nlohmann::json& json_data);

  bool query_smf_select_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& json_data);

 private:
  // cassandra_connector;
};
}  // namespace oai::udr::app

#endif
