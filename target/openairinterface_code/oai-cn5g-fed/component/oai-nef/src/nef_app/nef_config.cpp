/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nef_config.hpp"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>

#include "common_defs.h"
#include "fqdn.hpp"
#include "if.hpp"
#include "logger.hpp"
#include "nef_app.hpp"
#include "string.hpp"

using namespace std;
using namespace libconfig;
using namespace oai::nef::app;

extern nef_config nef_cfg;

nef_config::nef_config() : m_rw_lock(), pid_dir(), instance(0), sbi() {
  sbi.port                      = 80;
  sbi.http2_port                = 8080;
  sbi.api_version               = "v1";
  support_features.use_fqdn_dns = false;
  support_features.use_http2    = false;

  amf_addr.ipv4_addr.s_addr = INADDR_ANY;
  amf_addr.port             = 80;
  amf_addr.http2_port       = 8080;
  amf_addr.fqdn             = {};
  amf_addr.api_version      = "v1";

  smf_addr.ipv4_addr.s_addr = INADDR_ANY;
  smf_addr.port             = 80;
  smf_addr.http2_port       = 8080;
  smf_addr.fqdn             = {};
  smf_addr.api_version      = "v1";

  udm_addr.ipv4_addr.s_addr = INADDR_ANY;
  udm_addr.port             = 80;
  udm_addr.http2_port       = 8080;
  udm_addr.fqdn             = {};
  udm_addr.api_version      = "v1";
};

//------------------------------------------------------------------------------
nef_config::~nef_config() {}

//------------------------------------------------------------------------------
int nef_config::load_interface(const Setting& if_cfg, interface_cfg_t& cfg) {
  if_cfg.lookupValue(NEF_CONFIG_STRING_INTERFACE_NAME, cfg.if_name);
  util::trim(cfg.if_name);
  if (not boost::iequals(cfg.if_name, "none")) {
    std::string address = {};
    if_cfg.lookupValue(NEF_CONFIG_STRING_IPV4_ADDRESS, address);
    util::trim(address);
    if (boost::iequals(address, "read")) {
      if (get_inet_addr_infos_from_iface(
              cfg.if_name, cfg.addr4, cfg.network4, cfg.mtu)) {
        Logger::nef_app().error(
            "Could not read %s network interface configuration", cfg.if_name);
        return RETURNerror;
      }
    } else {
      std::vector<std::string> words;
      boost::split(
          words, address, boost::is_any_of("/"), boost::token_compress_on);
      if (words.size() != 2) {
        Logger::nef_app().error(
            "Bad value " NEF_CONFIG_STRING_IPV4_ADDRESS " = %s in config file",
            address.c_str());
        return RETURNerror;
      }
      unsigned char buf_in_addr[sizeof(struct in6_addr)];
      if (inet_pton(AF_INET, util::trim(words.at(0)).c_str(), buf_in_addr) ==
          1) {
        memcpy(&cfg.addr4, buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::nef_app().error(
            "In conversion: Bad value " NEF_CONFIG_STRING_IPV4_ADDRESS
            " = %s in config file",
            util::trim(words.at(0)).c_str());
        return RETURNerror;
      }
      cfg.network4.s_addr = htons(
          ntohs(cfg.addr4.s_addr) &
          0xFFFFFFFF << (32 - std::stoi(util::trim(words.at(1)))));
    }
    // Port
    if_cfg.lookupValue(NEF_CONFIG_STRING_PORT, cfg.port);

    // HTTP2 port
    if (!(if_cfg.lookupValue(
            NEF_CONFIG_STRING_SBI_HTTP2_PORT, cfg.http2_port))) {
      Logger::nef_app().error(NEF_CONFIG_STRING_SBI_HTTP2_PORT "failed");
      throw(NEF_CONFIG_STRING_SBI_HTTP2_PORT "failed");
    }

    // API VERSION
    if (!(if_cfg.lookupValue(NEF_CONFIG_STRING_API_VERSION, cfg.api_version))) {
      Logger::nef_app().error(NEF_CONFIG_STRING_API_VERSION "failed");
      throw(NEF_CONFIG_STRING_API_VERSION "failed");
    }
  }
  return RETURNok;
}

//------------------------------------------------------------------------------
int nef_config::load(const string& config_file) {
  Config cfg;
  unsigned char buf_in6_addr[sizeof(struct in6_addr)];

  // Read the file. If there is an error, report it and exit.
  try {
    cfg.readFile(config_file.c_str());
  } catch (const FileIOException& fioex) {
    Logger::nef_app().error(
        "I/O error while reading file %s - %s", config_file.c_str(),
        fioex.what());
    throw;
  } catch (const ParseException& pex) {
    Logger::nef_app().error(
        "Parse error at %s:%d - %s", pex.getFile(), pex.getLine(),
        pex.getError());
    throw;
  }

  const Setting& root = cfg.getRoot();

  try {
    const Setting& nef_cfg = root[NEF_CONFIG_STRING_NEF_CONFIG];
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror;
  }

  const Setting& nef_cfg = root[NEF_CONFIG_STRING_NEF_CONFIG];

  try {
    nef_cfg.lookupValue(NEF_CONFIG_STRING_INSTANCE, instance);
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().info(
        "%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    nef_cfg.lookupValue(NEF_CONFIG_STRING_PID_DIRECTORY, pid_dir);
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().info(
        "%s : %s, using defaults", nfex.what(), nfex.getPath());
  }

  try {
    const Setting& sbi_cfg = nef_cfg[NEF_CONFIG_STRING_INTERFACE_SBI];
    load_interface(sbi_cfg, sbi);
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror;
  }

  try {
    // AMF
    const Setting& amf_cfg = nef_cfg[NEF_CONFIG_STRING_AMF];
    load_nf_info(amf_cfg, amf_addr);
    // SMF
    const Setting& smf_cfg = nef_cfg[NEF_CONFIG_STRING_SMF];
    load_nf_info(smf_cfg, smf_addr);
    // SMF
    const Setting& udm_cfg = nef_cfg[NEF_CONFIG_STRING_UDM];
    load_nf_info(udm_cfg, udm_addr);
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().error("%s : %s", nfex.what(), nfex.getPath());
    return RETURNerror;
  }

  // Supported features
  try {
    const Setting& support_features_cfg =
        nef_cfg[NEF_CONFIG_STRING_SUPPORT_FEATURES];
    string opt;

    support_features_cfg.lookupValue(
        NEF_CONFIG_STRING_SUPPORT_FEATURES_USE_FQDN_DNS, opt);
    if (boost::iequals(opt, "yes")) {
      support_features.use_fqdn_dns = true;
    } else {
      support_features.use_fqdn_dns = false;
    }

    support_features_cfg.lookupValue(
        NEF_CONFIG_STRING_SUPPORT_FEATURES_USE_HTTP2, opt);
    if (boost::iequals(opt, "yes")) {
      support_features.use_http2 = true;
    } else {
      support_features.use_http2 = false;
    }
  } catch (const SettingNotFoundException& nfex) {
    Logger::nef_app().error(
        "%s : %s, using defaults", nfex.what(), nfex.getPath());
    return RETURNerror;
  }

  return true;
}

//------------------------------------------------------------------------------
void nef_config::load_nf_info(const Setting& nf_cfg, nf_addr_t& nf_addr) {
  string astring              = {};
  struct in_addr nf_ipv4_addr = {};
  unsigned int nf_port        = {0};
  std::string nf_api_version  = {};

  if (!support_features.use_fqdn_dns) {
    nf_cfg.lookupValue(NEF_CONFIG_STRING_IPV4_ADDRESS, astring);
    IPV4_STR_ADDR_TO_INADDR(
        util::trim(astring).c_str(), nf_ipv4_addr,
        "BAD IPv4 ADDRESS FORMAT FOR NRF !");
    nf_addr.ipv4_addr = nf_ipv4_addr;
    if (!(nf_cfg.lookupValue(NEF_CONFIG_STRING_PORT, nf_port))) {
      Logger::nef_app().error(NEF_CONFIG_STRING_PORT "failed");
      throw(NEF_CONFIG_STRING_PORT "failed");
    }
    nf_addr.port = nf_port;

    if (!(nf_cfg.lookupValue(NEF_CONFIG_STRING_API_VERSION, nf_api_version))) {
      Logger::nef_app().error(NEF_CONFIG_STRING_API_VERSION "failed");
      throw(NEF_CONFIG_STRING_API_VERSION "failed");
    }
    nf_addr.api_version = nf_api_version;
  } else {
    nf_cfg.lookupValue(NEF_CONFIG_STRING_FQDN_DNS, astring);
    uint8_t addr_type   = {0};
    std::string address = {};
    fqdn::resolve(astring, address, nf_port, addr_type);
    if (addr_type != 0) {  // IPv6
      // TODO:
      throw("DO NOT SUPPORT IPV6 ADDR FOR NF!");
    } else {  // IPv4
      IPV4_STR_ADDR_TO_INADDR(
          util::trim(address).c_str(), nf_ipv4_addr,
          "BAD IPv4 ADDRESS FORMAT FOR NF!");
      nf_addr.ipv4_addr = nf_ipv4_addr;
      // We hardcode nf port from config for the moment
      if (!(nf_cfg.lookupValue(NEF_CONFIG_STRING_PORT, nf_port))) {
        Logger::nef_app().error(NEF_CONFIG_STRING_PORT "failed");
        throw(NEF_CONFIG_STRING_PORT "failed");
      }
      nf_addr.port        = nf_port;
      nf_addr.api_version = "v1";  // TODO: to get API version from DNS
      nf_addr.fqdn        = astring;
    }
  }
}
//------------------------------------------------------------------------------
void nef_config::display() {
  Logger::nef_app().info(
      "==== OAI-CN5G %s v%s ====", PACKAGE_NAME, PACKAGE_VERSION);
  Logger::nef_app().info("Configuration NEF:");
  Logger::nef_app().info("- Instance ..............: %d\n", instance);
  Logger::nef_app().info("- PID dir ...............: %s\n", pid_dir.c_str());

  Logger::nef_app().info("- SBI Interface:");
  Logger::nef_app().info("    Interface name ......: %s", sbi.if_name.c_str());
  Logger::nef_app().info("    IPv4 Addr ...........: %s", inet_ntoa(sbi.addr4));
  Logger::nef_app().info("    Port ................: %d", sbi.port);
  Logger::nef_app().info("    HTTP2 port ..........: %d", sbi.http2_port);
  Logger::nef_app().info(
      "    API version..........: %s", sbi.api_version.c_str());

  // AMF
  Logger::nef_app().info("- AMF:");
  Logger::nef_app().info(
      "    IPv4 Addr ...........: %s",
      inet_ntoa(*((struct in_addr*) &amf_addr.ipv4_addr)));
  Logger::nef_app().info("    Port ................: %lu  ", amf_addr.port);
  Logger::nef_app().info(
      "    HTTP/2 port .........: %lu  ", amf_addr.http2_port);
  Logger::nef_app().info(
      "    API version .........: %s", amf_addr.api_version.c_str());
  if (support_features.use_fqdn_dns)
    Logger::nef_app().info(
        "    FQDN ................: %s", amf_addr.fqdn.c_str());

  // SMF
  Logger::nef_app().info("- SMF:");
  Logger::nef_app().info(
      "    IPv4 Addr ...........: %s",
      inet_ntoa(*((struct in_addr*) &smf_addr.ipv4_addr)));
  Logger::nef_app().info("    Port ................: %lu  ", smf_addr.port);
  Logger::nef_app().info(
      "    HTTP/2 port .........: %lu  ", smf_addr.http2_port);
  Logger::nef_app().info(
      "    API version .........: %s", smf_addr.api_version.c_str());
  if (support_features.use_fqdn_dns)
    Logger::nef_app().info(
        "    FQDN ................: %s", smf_addr.fqdn.c_str());

  // UDM
  Logger::nef_app().info("- UDM:");
  Logger::nef_app().info(
      "    IPv4 Addr ...........: %s",
      inet_ntoa(*((struct in_addr*) &udm_addr.ipv4_addr)));
  Logger::nef_app().info("    Port ................: %lu  ", udm_addr.port);
  Logger::nef_app().info(
      "    HTTP/2 port .........: %lu  ", udm_addr.http2_port);
  Logger::nef_app().info(
      "    API version .........: %s", udm_addr.api_version.c_str());
  if (support_features.use_fqdn_dns)
    Logger::nef_app().info(
        "    FQDN ................: %s", udm_addr.fqdn.c_str());

  Logger::nef_app().info("- Supported Features:");
  Logger::nef_app().info(
      "    Use FQDN ..............: %s",
      support_features.use_fqdn_dns ? "Yes" : "No");
  Logger::nef_app().info(
      "    Use HTTP2..............: %s",
      support_features.use_http2 ? "Yes" : "No");
}

//------------------------------------------------------------------------------
std::string nef_config::get_event_exposure_url() {
  return std::string(inet_ntoa(sbi.addr4)) + ":" + std::to_string(sbi.port) +
         NNEF_EVENT_EXPOSURE_BASE + sbi.api_version;
}

//------------------------------------------------------------------------------
std::string nef_config::get_event_exposure_subscription_url() {
  return get_event_exposure_url() + NNEF_EE_SUBSCRIPTION_URL;
}

//------------------------------------------------------------------------------
std::string nef_config::get_event_exposure_subscription_notify_url() {
  return get_event_exposure_url() + NNEF_EE_SUBSCRIPTION_NOTIFY_URL;
}

//------------------------------------------------------------------------------
std::string nef_config::get_amf_event_exposure_url() {
  return std::string(inet_ntoa(amf_addr.ipv4_addr)) + ":" +
         std::to_string(amf_addr.port) + NAMF_EVENT_EXPOSURE_BASE +
         amf_addr.api_version + "/subscriptions";
}
