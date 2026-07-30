/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "policy_storage_yaml.hpp"
#include "logger.hpp"
#include <string>
#include <sstream>

using namespace oai::pcf::app::sm_policy;
using namespace oai::model::pcf;
using namespace oai::model::common;

void policy_storage_yaml::set_default_decision(
    const SmPolicyDecision& decision) {
  std::shared_ptr<policy_decision> desc =
      std::make_shared<policy_decision>(decision);

  default_decision = desc;
  notify_subscribers(desc);
}

void policy_storage_yaml::insert_supi_decision(
    const std::string& supi, const SmPolicyDecision& decision) {
  std::unique_lock supi_decision_lock(m_supi_policy_decisions_mutex);

  std::shared_ptr<supi_policy_decision> desc =
      std::make_shared<supi_policy_decision>(supi, decision);

  m_supi_policy_decisions.insert(std::make_pair(supi, desc));
  supi_decision_lock.unlock();
  notify_subscribers(desc);
}

void policy_storage_yaml::insert_dnn_decision(
    const std::string& dnn, const SmPolicyDecision& decision) {
  std::unique_lock dnn_decision_lock(m_dnn_policy_decisions_mutex);

  std::shared_ptr<dnn_policy_decision> desc =
      std::make_shared<dnn_policy_decision>(dnn, decision);

  m_dnn_policy_decisions.insert(std::make_pair(dnn, desc));
  dnn_decision_lock.unlock();
  notify_subscribers(desc);
}

void policy_storage_yaml::insert_slice_decision(
    const Snssai& slice, const SmPolicyDecision& decision) {
  std::unique_lock slice_decision_lock(m_slice_policy_decisions_mutex);

  std::shared_ptr<slice_policy_decision> desc =
      std::make_shared<slice_policy_decision>(slice, decision);

  m_slice_policy_decisions.insert(std::make_pair(slice, desc));
  slice_decision_lock.unlock();
  notify_subscribers(desc);
}

std::shared_ptr<policy_decision> policy_storage_yaml::find_policy(
    const SmPolicyContextData& context) {
  std::string msg_base = "SM Policy request from SUPI:";
  std::string supi     = context.getSupi();

  std::shared_ptr<policy_decision> res_ptr;

  // First, check based on SUPI, then DNN, then Slice, then global default rule.
  std::shared_lock lock_supi(m_supi_policy_decisions_mutex);
  auto got_supi = m_supi_policy_decisions.find(context.getSupi());

  if (got_supi == m_supi_policy_decisions.end()) {
    Logger::pcf_app().debug(
        "%s %s - Did not find SUPI policy", msg_base.c_str(), supi.c_str());
    std::shared_lock lock_dnn(m_dnn_policy_decisions_mutex);
    auto got_dnn = m_dnn_policy_decisions.find(context.getDnn());

    if (got_dnn == m_dnn_policy_decisions.end()) {
      Logger::pcf_app().debug(
          "%s %s - Did not find DNN policy", msg_base.c_str(), supi.c_str());
      std::shared_lock lock_slice(m_slice_policy_decisions_mutex);
      auto got_slice = m_slice_policy_decisions.find(context.getSliceInfo());

      if (got_slice == m_slice_policy_decisions.end()) {
        Logger::pcf_app().debug(
            "%s %s - Did not find slice policy", msg_base.c_str(),
            supi.c_str());

        if (!default_decision) {
          Logger::pcf_app().debug(
              "%s %s - Did not find default policy", msg_base.c_str(),
              supi.c_str());

          return res_ptr;  // null
        } else {
          Logger::pcf_app().debug(
              "%s %s - Decide based on default policy", msg_base.c_str(),
              supi.c_str());
          return default_decision;
        }
      } else {
        Logger::pcf_app().debug("%s Decide based on slice", msg_base.c_str());
        return got_slice->second;
      }
    } else {
      Logger::pcf_app().debug("%s Decide based on DNN", msg_base.c_str());
      return got_dnn->second;
    }
  } else {
    Logger::pcf_app().debug("%s Decide based on SUPI", msg_base.c_str());
    return got_supi->second;
  }
}

void policy_storage_yaml::notify_subscribers(
    const std::shared_ptr<policy_decision>& /* decision */) {
  // TODO
}

void policy_storage_yaml::subscribe_to_decision_change(
    std::function<void(std::shared_ptr<policy_decision>&)> /* callback */) {
  // TODO implement me
}

void policy_storage_yaml::insert_associations(
    const oai::model::pcf::SmPolicyContextData& context,
    const std::string& association_id) {
  Logger::pcf_app().debug(
      "Inserting into association maps [IPv4 -> %s, SUPI -> %s, DNN -> %s] : "
      "[Assoc Id -> %s]",
      context.getIpv4Address().c_str(), context.getSupi().c_str(),
      context.getDnn().c_str(), association_id.c_str());
  policy_storage_yaml::insert_ip_association(
      context.getIpv4Address(), association_id);

  policy_storage_yaml::insert_supi_association(
      context.getSupi(), association_id);

  policy_storage_yaml::insert_dnn_association(context.getDnn(), association_id);
}

void policy_storage_yaml::insert_ip_association(
    const std::string& ip, const std::string& association_id) {
  std::unique_lock ip_association_lock(m_ip_to_association_map_mutex);

  m_ip_to_association_map.insert(std::make_pair(ip, association_id));
  ip_association_lock.unlock();
}

void policy_storage_yaml::insert_supi_association(
    const std::string& supi, const std::string& association_id) {
  std::unique_lock supi_to_association_lock(m_supi_to_association_map_mutex);

  m_supi_to_association_map.insert(std::make_pair(supi, association_id));
  supi_to_association_lock.unlock();
}

void policy_storage_yaml::insert_dnn_association(
    const std::string& dnn, const std::string& association_id) {
  std::unique_lock dnn_to_association_lock(m_dnn_to_association_map_mutex);

  auto assocs = m_dnn_to_association_map.find(dnn);
  if (assocs == m_dnn_to_association_map.end()) {
    // Insert with empty vector
    std::vector<std::string> assocs_v = {association_id};
    m_dnn_to_association_map.insert(std::make_pair(dnn, assocs_v));
  } else {
    // Insert into vector that was found
    assocs->second.push_back(association_id);
  }

  dnn_to_association_lock.unlock();
}

std::shared_ptr<std::string> policy_storage_yaml::find_association(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn) {
  std::string msg_base = "Finding SM Association: ";

  // First, check based on SUPI, then DNN, then Slice, then global default rule.
  std::shared_lock lock_supi(m_ip_to_association_map_mutex);
  auto got_ip = m_ip_to_association_map.end();
  if (ipv4.has_value() &&
      (got_ip = m_ip_to_association_map.find(ipv4.value())) ==
          m_ip_to_association_map.end()) {
    Logger::pcf_app().debug(
        "%s - Did not find for IPv4 -> %s", msg_base.c_str(),
        ipv4.value().c_str());

    auto got_supi = m_supi_to_association_map.end();
    if (supi.has_value() &&
        (got_supi = m_supi_to_association_map.find(supi.value())) ==
            m_supi_to_association_map.end()) {
      Logger::pcf_app().debug(
          "%s - Did not find for SUPI -> %s", msg_base.c_str(),
          supi.value().c_str());

      // TODO [PAS] handle DNN
      /* The since during creation of association, the IP address might be
       * absent, we need to make sure either it's updated or the we loop through
       * the associations on DNN that have had the an association with the IP
       * updated i.e., for each assoc in DNN find one with IP == Ipv4 */

    } else if (got_supi != m_supi_to_association_map.end()) {
      Logger::pcf_app().debug(
          "%s - Decide based on SUPI -> %s", msg_base.c_str(),
          supi.value().c_str());
      return std::make_shared<std::string>(got_supi->second);
    }
  } else if (got_ip != m_ip_to_association_map.end()) {
    Logger::pcf_app().debug(
        "%s - Decide based on Ipv4 -> %s", msg_base.c_str(),
        ipv4.value().c_str());
    return std::make_shared<std::string>(got_ip->second);
  }
  Logger::pcf_app().debug(
      "%s - Failed to find association, returning NULL", msg_base.c_str());
  return nullptr;
}

std::string policy_storage_yaml::to_string() const {
  std::shared_lock supi_lock(m_supi_policy_decisions_mutex);
  std::shared_lock dnn_lock(m_dnn_policy_decisions_mutex);
  std::shared_lock slice_lock(m_slice_policy_decisions_mutex);

  std::stringstream ss;

  std::string output;

  ss << "Policy Storage: \n";
  ss << " - Default Decision: \n";
  if (default_decision) {
    ss << " -- " << *default_decision << "\n";
  } else {
    ss << " -- No Default Decision\n";
  }
  ss << " - Slice Decisions: \n";
  if (!m_slice_policy_decisions.empty()) {
    for (const auto& slice_desc : m_slice_policy_decisions) {
      ss << " -- " << *slice_desc.second << "\n";
    }
  } else {
    ss << " -- No Slice Decisions\n";
  }
  ss << " - DNN Decisions: \n";
  if (!m_dnn_policy_decisions.empty()) {
    for (const auto& dnn_desc : m_dnn_policy_decisions) {
      ss << " -- " << *dnn_desc.second << "\n";
    }
  } else {
    ss << " -- No DNN Decisions\n";
  }

  if (!m_supi_policy_decisions.empty()) {
    ss << " - SUPI Decisions: \n";
    for (const auto& supi_desc : m_supi_policy_decisions) {
      ss << " -- " << *supi_desc.second << "\n";
    }
  } else {
    ss << " - No SUPI Decisions\n";
  }

  return ss.str();
}

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::policy_storage_yaml& storage) {
  return os << storage.to_string();
}
