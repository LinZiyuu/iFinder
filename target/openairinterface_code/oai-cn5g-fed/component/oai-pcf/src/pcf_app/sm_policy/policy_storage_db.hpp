/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <shared_mutex>
#include <optional>
#include <database_wrapper_abstraction.hpp>
#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"
#include "policy_storage.hpp"

namespace oai::pcf::app::sm_policy {
/**
 * @brief Class connected to policies stored in the database, added through
 * provisioning requests.
 *
 */
class policy_storage_db : public policy_storage {
 public:
  policy_storage_db();

  std::shared_ptr<policy_decision> find_policy(
      const oai::model::pcf::SmPolicyContextData& context);

  void notify_subscribers(const std::shared_ptr<policy_decision>& decision);

  void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<policy_decision>&)> callback);

  void insert_supi_decision(
      const std::string& supi,
      const oai::model::pcf::SmPolicyDecision& decision);

  void insert_dnn_decision(
      const std::string& dnn,
      const oai::model::pcf::SmPolicyDecision& decision);

  void insert_slice_decision(
      const oai::model::common::Snssai&,
      const oai::model::pcf::SmPolicyDecision& decision);

  void insert_associations(
      const oai::model::pcf::SmPolicyContextData& context,
      const std::string& association_id);

  void insert_ip_association(
      const std::string& dnn, const std::string& association_id);

  void insert_supi_association(
      const std::string& supi, const std::string& association_id);

  void insert_dnn_association(
      const std::string& dnn, const std::string& association_id);

  std::shared_ptr<std::string> find_association(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn);
};

}  // namespace oai::pcf::app::sm_policy