/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "policy_decision.hpp"
#include "PolicyControlRequestTrigger_anyOf.h"
#include "logger.hpp"
#include <sstream>

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::app;

typedef PolicyControlRequestTrigger_anyOf::ePolicyControlRequestTrigger_anyOf E;

status_code policy_decision::decide(
    const SmPolicyContextData& /* context */,
    SmPolicyDecision& decision) const {
  // default rule, so just reply with the decision
  decision = m_decision;
  return status_code::CREATED;
}

const SmPolicyDecision& policy_decision::get_sm_policy_decision() const {
  return m_decision;
}

const void policy_decision::set_sm_policy_decision(SmPolicyDecision& decision) {
  m_decision = decision;
}

status_code policy_decision::handle_plmn_change(
    SmPolicyContextData& orig_context, const SmPolicyUpdateContextData& update,
    std::string& problem_details) {
  // TODO actually also change m_decision, method should not be static

  if (update.servingNetworkIsSet()) {
    orig_context.setServingNetwork(update.getServingNetwork());
    return status_code::OK;
  }
  problem_details = "Serving Network is not set";
  return status_code::INVALID_PARAMETERS;
}

status_code policy_decision::handle_access_type_change(
    SmPolicyContextData& orig_context, const SmPolicyUpdateContextData& update,
    std::string& problem_details) {
  // TODO actually also change m_decision, method should not be static
  if (update.accessTypeIsSet()) {
    orig_context.setAccessType(update.getAccessType());
    return status_code::OK;
  }
  if (update.addAccessInfoIsSet()) {
    Logger::pcf_app().error("ATSSS not supported");
    problem_details = "ATSSS not supported";
    return status_code::INVALID_PARAMETERS;
  }
  return status_code::INVALID_PARAMETERS;
}

status_code policy_decision::handle_ip_address_change(
    SmPolicyContextData& orig_context, const SmPolicyUpdateContextData& update,
    std::string& problem_details) {
  // TODO actually also change m_decision, method should not be static
  problem_details  = "";
  status_code code = status_code::INVALID_PARAMETERS;
  if (update.ipv4AddressIsSet()) {
    orig_context.setIpv4Address(update.getIpv4Address());
    code = status_code::OK;
  }
  if (update.ipv6AddressPrefixIsSet()) {
    orig_context.setIpv6AddressPrefix(update.getIpv6AddressPrefix());
    code = status_code::OK;
  }
  if (update.relIpv4AddressIsSet() || update.relIpv6AddressPrefixIsSet()) {
    Logger::pcf_app().debug("Ignore released IP address");
    code = status_code::OK;
  }
  if (update.addIpv6AddrPrefixesIsSet() || update.relIpv6AddressPrefixIsSet()) {
    Logger::pcf_app().error("Multiple IPv6 addresses not supported");
    problem_details = "Multiple IPv6 addresses not supported";
    code            = status_code::INVALID_PARAMETERS;
  }

  if (code != status_code::OK) {
    std::string det = "IPv4 or IPv6 address needs to be specified";

    problem_details = !problem_details.empty() ?
                          problem_details.append(" | ").append(det) :
                          det;
  }
  return code;
}

status_code policy_decision::handle_rat_type_change(
    SmPolicyContextData& orig_context, const SmPolicyUpdateContextData& update,
    std::string& problem_details) {
  // TODO actually also change m_decision, method should not be static
  status_code code = status_code::INVALID_PARAMETERS;
  if (update.ratTypeIsSet()) {
    orig_context.setRatType(update.getRatType());
    code = status_code::OK;
  }
  if (update.accessTypeIsSet()) {
    orig_context.setAccessType(update.getAccessType());
    // dont set status code here because access type alone is not enough
  }

  if (update.addAccessInfoIsSet()) {
    orig_context.setAddAccessInfo(update.getAddAccessInfo());
    code = status_code::OK;
  }
  if (code != status_code::OK) {
    problem_details =
        "RAT type or additional access information needs to be set";
  }

  return code;
}

status_code policy_decision::redecide(
    SmPolicyContextData& original_context,
    const SmPolicyUpdateContextData& update_data,
    SmPolicyDecision& new_decision, std::string& problem_details) {
  status_code status = status_code::OK;
  // that is not very beautiful, but that is how the API is designed
  // (TS 29.512 4.2.4.2)
  if (update_data.repPolicyCtrlReqTriggersIsSet()) {
    std::vector<PolicyControlRequestTrigger> triggers =
        update_data.getRepPolicyCtrlReqTriggers();

    for (auto it = std::begin(triggers); it != std::end(triggers); it++) {
      if (status != status_code::OK)
        break;  // leave for loop as an error happened

      switch (it->getEnumValue()) {
        case E::PLMN_CH:
          status = handle_plmn_change(
              original_context, update_data, problem_details);
          break;
        case E::RES_MO_RE:
          Logger::pcf_app().error("RES_MO_RE not supported");
          break;
        case E::AC_TY_CH:
          status = handle_access_type_change(
              original_context, update_data, problem_details);
          break;
        case E::UE_IP_CH:
          status = handle_ip_address_change(
              original_context, update_data, problem_details);
          break;
        case E::UE_MAC_CH:
          Logger::pcf_app().error("UE_MAC_CH not supported");
          break;
        case E::AN_CH_COR:
          Logger::pcf_app().error("AN_CH_COR not supported");
          break;
        case E::US_RE:
          Logger::pcf_app().error("US_RE not supported");
          break;
        case E::APP_STA:
          Logger::pcf_app().error("APP_STA not supported");
          break;
        case E::APP_STO:
          Logger::pcf_app().error("APP_STO not supported");
          break;
        case E::AN_INFO:
          Logger::pcf_app().error("AN_INFO not supported");
          break;
        case E::CM_SES_FAIL:
          Logger::pcf_app().error("CM_SES_FAIL not supported");
          break;
        case E::PS_DA_OFF:
          Logger::pcf_app().error("PS_DA_OFF not supported");
          break;
        case E::DEF_QOS_CH:
          Logger::pcf_app().error("DEF_QOS_CH not supported");
          break;
        case E::SE_AMBR_CH:
          Logger::pcf_app().error("SE_AMBR_CH not supported");
          break;
        case E::QOS_NOTIF:
          Logger::pcf_app().error("QOS_NOTIF not supported");
          break;
        case E::NO_CREDIT:
          Logger::pcf_app().error("NO_CREDIT not supported");
          break;
        case E::REALLO_OF_CREDIT:
          Logger::pcf_app().error("REALLO_OF_CREDIT not supported");
          break;
        case E::PRA_CH:
          Logger::pcf_app().error("PRA_CH not supported");
          break;
        case E::SAREA_CH:
          Logger::pcf_app().error("SAREA_CH not supported");
          break;
        case E::SCNN_CH:
          Logger::pcf_app().error("SCNN_CH not supported");
          break;
        case E::RE_TIMEOUT:
          Logger::pcf_app().error("RE_TIMEOUT not supported");
          break;
        case E::RES_RELEASE:
          Logger::pcf_app().error("RES_RELEASE not supported");
          break;
        case E::SUCC_RES_ALLO:
          Logger::pcf_app().error("SUCC_RES_ALLO not supported");
          break;
        case E::RAT_TY_CH:
          status = handle_rat_type_change(
              original_context, update_data, problem_details);
          break;
        case E::REF_QOS_IND_CH:
          Logger::pcf_app().error("REF_QOS_IND_CH not supported");
          break;
        case E::UE_STATUS_RESUME:
          Logger::pcf_app().error("UE_STATUS_RESUME not supported");
          break;
        case E::UE_TZ_CH:
          Logger::pcf_app().error("UE_TZ_CH not supported");
          break;
        case E::AUTH_PROF_CH:
          Logger::pcf_app().error("AUTH_PROF_CH not supported");
          break;
        case E::QOS_MONITORING:
          Logger::pcf_app().error("QOS_MONITORING not supported");
          break;
        case E::SCELL_CH:
          Logger::pcf_app().error("SCELL_CH not supported");
          break;
        case E::EPS_FALLBACK:
          Logger::pcf_app().error("EPS_FALLBACK not supported");
          break;
        case E::MA_PDU:
          Logger::pcf_app().error("MA_PDU not supported");
          break;
        case E::_5G_RG_JOIN:
          Logger::pcf_app().error("5G_RG_JOIN not supported");
          break;
        case E::_5G_RG_LEAVE:
          Logger::pcf_app().error("5G_RG_LEAVE not supported");
          break;
        default:
          Logger::pcf_app().error("Unsupported parameter");
      }
    }
  }

  new_decision = m_decision;
  return status;
}

std::string policy_decision::to_string() const {
  std::stringstream ss;
  ss << m_decision;
  return ss.str();
}

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::policy_decision& storage) {
  return (os << storage.to_string());
}
