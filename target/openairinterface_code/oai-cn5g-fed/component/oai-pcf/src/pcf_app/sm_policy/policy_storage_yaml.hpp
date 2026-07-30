/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_STORAGE_SEEN
#define FILE_POLICY_STORAGE_SEEN

#include <string>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <optional>

#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"
#include "Snssai.h"
#include "policy_decision.hpp"
#include "slice_policy_decision.hpp"
#include "dnn_policy_decision.hpp"
#include "supi_policy_decision.hpp"
#include "snssai_hasher.hpp"
#include "policy_storage.hpp"

namespace oai::pcf::app::sm_policy {
/**
 * @brief Class to store policies, either pre-configured using files and/or AF
 * or provisioning requests
 *
 */

class policy_storage_yaml : public policy_storage {
 private:
  void notify_subscribers(const std::shared_ptr<policy_decision>& decision);

  std::unordered_map<
      oai::model::common::Snssai,
      std::shared_ptr<oai::pcf::app::sm_policy::slice_policy_decision>,
      oai::pcf::app::sm_policy::snssai_hasher>
      m_slice_policy_decisions;

  std::unordered_map<
      std::string,
      std::shared_ptr<oai::pcf::app::sm_policy::dnn_policy_decision>>
      m_dnn_policy_decisions;

  std::unordered_map<
      std::string,
      std::shared_ptr<oai::pcf::app::sm_policy::supi_policy_decision>>
      m_supi_policy_decisions;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_decision> default_decision;

  mutable std::shared_mutex m_slice_policy_decisions_mutex;
  mutable std::shared_mutex m_dnn_policy_decisions_mutex;
  mutable std::shared_mutex m_supi_policy_decisions_mutex;

  // ip_association_map < IP, association_id>
  std::unordered_map<std::string, std::string> m_ip_to_association_map;
  // supi_association_map <supi, association_id>
  std::unordered_map<std::string, std::string> m_supi_to_association_map;
  // dnn_to_association_map < DNN, vector<association_id>>
  std::unordered_map<std::string, std::vector<std::string>>
      m_dnn_to_association_map;

  mutable std::shared_mutex m_ip_to_association_map_mutex;
  mutable std::shared_mutex m_supi_to_association_map_mutex;
  mutable std::shared_mutex m_dnn_to_association_map_mutex;

 public:
  explicit policy_storage_yaml()                  = default;
  policy_storage_yaml(policy_storage_yaml const&) = delete;
  void operator=(policy_storage_yaml const&) = delete;

  // TODO methods to update and delete policies
  void insert_supi_decision(
      const std::string& supi,
      const oai::model::pcf::SmPolicyDecision& decision);

  void insert_dnn_decision(
      const std::string& dnn,
      const oai::model::pcf::SmPolicyDecision& decision);

  void insert_slice_decision(
      const oai::model::common::Snssai&,
      const oai::model::pcf::SmPolicyDecision& decision);

  void set_default_decision(const oai::model::pcf::SmPolicyDecision& decision);

  /**
   * @brief Finds a policy based on the existing supi, dnn, slice and default
   * policies in that order.
   *
   * @param context  The policy context containing supi or dnn or snssai
   * @param chosen_decision
   * decision base class
   * @return pointer to the object implementing the chosen, null in case no
   * decision can be found
   */
  std::shared_ptr<policy_decision> find_policy(
      const oai::model::pcf::SmPolicyContextData& context);

  /**
   * @brief Calls the callback when any of the policies have been updated
   *
   * @param callback
   */
  void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<policy_decision>&)> callback);

  std::string to_string() const;

  // TODO methods to update and delete
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

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::policy_storage_yaml& storage);

#endif
