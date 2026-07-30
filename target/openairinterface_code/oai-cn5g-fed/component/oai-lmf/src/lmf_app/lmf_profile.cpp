/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "lmf_profile.hpp"
#include "logger.hpp"
#include "string.hpp"

using namespace oai::lmf::app;

//------------------------------------------------------------------------------
void lmf_profile::set_nf_instance_id(const std::string& instance_id) {
  nf_instance_id = instance_id;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_instance_id(std::string& instance_id) const {
  instance_id = nf_instance_id;
}

//------------------------------------------------------------------------------
std::string lmf_profile::get_nf_instance_id() const {
  Logger::lmf_app().debug("get_nf_instance_id: %s", nf_instance_id.c_str());
  return nf_instance_id;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_instance_name(const std::string& instance_name) {
  nf_instance_name = instance_name;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_instance_name(std::string& instance_name) const {
  instance_name = nf_instance_name;
}

//------------------------------------------------------------------------------
std::string lmf_profile::get_nf_instance_name() const {
  return nf_instance_name;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_type(const std::string& type) {
  nf_type = type;
}

//------------------------------------------------------------------------------
std::string lmf_profile::get_nf_type() const {
  return nf_type;
}
//------------------------------------------------------------------------------
void lmf_profile::set_nf_status(const std::string& status) {
  nf_status = status;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_status(std::string& status) const {
  status = nf_status;
}

//------------------------------------------------------------------------------
std::string lmf_profile::get_nf_status() const {
  return nf_status;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_heartBeat_timer(const int32_t& timer) {
  heartBeat_timer = timer;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_heartBeat_timer(int32_t& timer) const {
  timer = heartBeat_timer;
}

//------------------------------------------------------------------------------
int32_t lmf_profile::get_nf_heartBeat_timer() const {
  return heartBeat_timer;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_priority(const uint16_t& p) {
  priority = p;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_priority(uint16_t& p) const {
  p = priority;
}

//------------------------------------------------------------------------------
uint16_t lmf_profile::get_nf_priority() const {
  return priority;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_capacity(const uint16_t& c) {
  capacity = c;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_capacity(uint16_t& c) const {
  c = capacity;
}

//------------------------------------------------------------------------------
uint16_t lmf_profile::get_nf_capacity() const {
  return capacity;
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_snssais(const std::vector<snssai_t>& s) {
  snssais = s;
}

//------------------------------------------------------------------------------
void lmf_profile::get_nf_snssais(std::vector<snssai_t>& s) const {
  s = snssais;
}

//------------------------------------------------------------------------------
void lmf_profile::add_snssai(const snssai_t& s) {
  snssais.push_back(s);
}

//------------------------------------------------------------------------------
void lmf_profile::set_nf_ipv4_addresses(const std::vector<struct in_addr>& a) {
  ipv4_addresses = a;
}

//------------------------------------------------------------------------------
void lmf_profile::add_nf_ipv4_addresses(const struct in_addr& a) {
  ipv4_addresses.push_back(a);
}
//------------------------------------------------------------------------------
void lmf_profile::get_nf_ipv4_addresses(std::vector<struct in_addr>& a) const {
  a = ipv4_addresses;
}

//------------------------------------------------------------------------------
void lmf_profile::set_lmf_info(const lmf_info_t& s) {
  lmf_info = s;
}

//------------------------------------------------------------------------------
void lmf_profile::get_lmf_info(lmf_info_t& s) const {
  s = lmf_info;
}

//------------------------------------------------------------------------------
void lmf_profile::display() const {
  Logger::lmf_app().debug("- NF instance info");
  Logger::lmf_app().debug("    Instance ID: %s", nf_instance_id.c_str());
  Logger::lmf_app().debug("    Instance name: %s", nf_instance_name.c_str());
  Logger::lmf_app().debug("    Instance type: %s", nf_type.c_str());
  Logger::lmf_app().debug("    Instance fqdn: %s", fqdn.c_str());
  Logger::lmf_app().debug("    Status: %s", nf_status.c_str());
  Logger::lmf_app().debug("    HeartBeat timer: %d", heartBeat_timer);
  Logger::lmf_app().debug("    Priority: %d", priority);
  Logger::lmf_app().debug("    Capacity: %d", capacity);
  // SNSSAIs
  if (snssais.size() > 0) {
    Logger::lmf_app().debug("    SNSSAI:");
  }
  for (auto s : snssais) {
    Logger::lmf_app().debug("        SST, SD: %d, %s", s.sST, s.sD.c_str());
  }

  // IPv4 Addresses
  if (ipv4_addresses.size() > 0) {
    Logger::lmf_app().debug("    IPv4 Addr:");
  }
  for (auto address : ipv4_addresses) {
    Logger::lmf_app().debug("        %s", inet_ntoa(address));
  }

  Logger::lmf_app().debug("\tLMF Info");
  Logger::lmf_app().debug("\t\t LmfId: %s", lmf_info.lmfId.c_str());
  /* TODO: is this needed in lmf */

  Logger::lmf_app().debug("\t\t ServingClientTypes: ");
  for (auto clientType : lmf_info.servingClientTypes) {
    Logger::lmf_app().debug("\t\t\t %s", clientType.c_str());
  }

  Logger::lmf_app().debug("\t\t ServingAccessTypes: ");
  for (auto accessType : lmf_info.servingAccessTypes) {
    Logger::lmf_app().debug("\t\t\t %s", accessType.c_str());
  }

  Logger::lmf_app().debug("\t\t ServingAnNodeTypes: ");
  for (auto nodeType : lmf_info.servingAnNodeTypes) {
    Logger::lmf_app().debug("\t\t\t %s", nodeType.c_str());
  }

  Logger::lmf_app().debug("\t\t ServingRatTypes: ");
  for (auto ratType : lmf_info.servingRatTypes) {
    Logger::lmf_app().debug("\t\t\t %s", ratType.c_str());
  }
}

//------------------------------------------------------------------------------
void lmf_profile::to_json(nlohmann::json& data) const {
  data["nfInstanceId"]   = nf_instance_id;
  data["nfInstanceName"] = nf_instance_name;
  data["nfType"]         = nf_type;
  data["nfStatus"]       = nf_status;
  data["heartBeatTimer"] = heartBeat_timer;
  // SNSSAIs
  data["sNssais"] = nlohmann::json::array();
  for (auto s : snssais) {
    nlohmann::json tmp = {};
    tmp["sst"]         = s.sST;
    tmp["sd"]          = s.sD;
    data["sNssais"].push_back(tmp);
  }
  data["fqdn"] = fqdn;
  // ipv4_addresses
  data["ipv4Addresses"] = nlohmann::json::array();
  for (auto address : ipv4_addresses) {
    nlohmann::json tmp = inet_ntoa(address);
    data["ipv4Addresses"].push_back(tmp);
  }

  data["priority"] = priority;
  data["capacity"] = capacity;

  // LMF Info
  data["lmfInfo"]["lmfId"]              = lmf_info.lmfId;
  data["lmfInfo"]["servingClientTypes"] = nlohmann::json::array();
  data["lmfInfo"]["servingAccessTypes"] = nlohmann::json::array();
  data["lmfInfo"]["servingAnNodeTypes"] = nlohmann::json::array();
  data["lmfInfo"]["servingRatTypes"]    = nlohmann::json::array();
  for (auto clientType : lmf_info.servingClientTypes) {
    data["lmfInfo"]["servingClientTypes"].push_back(clientType);
  }
  for (auto accessType : lmf_info.servingAccessTypes) {
    data["lmfInfo"]["servingAccessTypes"].push_back(accessType);
  }
  for (auto nodeType : lmf_info.servingAnNodeTypes) {
    data["lmfInfo"]["servingAnNodeTypes"].push_back(nodeType);
  }
  for (auto ratType : lmf_info.servingRatTypes) {
    data["lmfInfo"]["servingRatTypes"].push_back(ratType);
  }

  Logger::lmf_app().debug("lmf profile to JSON:\n %s", data.dump().c_str());
}

//------------------------------------------------------------------------------
void lmf_profile::from_json(const nlohmann::json& data) {
  if (data.find("nfInstanceId") != data.end()) {
    nf_instance_id = data["nfInstanceId"].get<std::string>();
  }

  if (data.find("nfInstanceName") != data.end()) {
    nf_instance_name = data["nfInstanceName"].get<std::string>();
  }

  if (data.find("nfType") != data.end()) {
    nf_type = data["nfType"].get<std::string>();
  }

  if (data.find("nfStatus") != data.end()) {
    nf_status = data["nfStatus"].get<std::string>();
  }

  if (data.find("heartBeatTimer") != data.end()) {
    heartBeat_timer = data["heartBeatTimer"].get<int>();
  }
  // sNssais
  if (data.find("sNssais") != data.end()) {
    for (auto it : data["sNssais"]) {
      snssai_t s = {};
      s.sST      = it["sst"].get<int>();
      s.sD       = it["sd"].get<std::string>();
      snssais.push_back(s);
    }
  }

  if (data.find("ipv4Addresses") != data.end()) {
    nlohmann::json addresses = data["ipv4Addresses"];

    for (auto it : addresses) {
      struct in_addr addr4 = {};
      std::string address  = it.get<std::string>();
      unsigned char buf_in_addr[sizeof(struct in_addr)];
      if (inet_pton(AF_INET, oai::utils::trim(address).c_str(), buf_in_addr) ==
          1) {
        memcpy(&addr4, buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::lmf_app().warn(
            "Address conversion: Bad value %s",
            oai::utils::trim(address).c_str());
      }
      add_nf_ipv4_addresses(addr4);
    }
  }

  if (data.find("priority") != data.end()) {
    priority = data["priority"].get<int>();
  }

  if (data.find("capacity") != data.end()) {
    capacity = data["capacity"].get<int>();
  }

  // LMF info
  if (data.find("lmfInfo") != data.end()) {
    nlohmann::json info = data["lmfInfo"];
    if (info.find("lmfId") != info.end()) {
      lmf_info.lmfId = info["lmfId"].get<std::string>();
    }
    if (info.find("servingClientTypes") != info.end()) {
      nlohmann::json servingClientTypes = data["lmfInfo"]["servingClientTypes"];
      for (auto clientType : servingClientTypes) {
        lmf_info.servingClientTypes.push_back(clientType);
      }
    }
    if (info.find("servingAccessTypes") != info.end()) {
      nlohmann::json servingAccessTypes = data["lmfInfo"]["servingAccessTypes"];
      for (auto accessType : servingAccessTypes) {
        lmf_info.servingAccessTypes.push_back(accessType);
      }
    }
    if (info.find("servingAnNodeTypes") != info.end()) {
      nlohmann::json servingAnNodeTypes = data["lmfInfo"]["servingAnNodeTypes"];
      for (auto nodeType : servingAnNodeTypes) {
        lmf_info.servingAnNodeTypes.push_back(nodeType);
      }
    }
    if (info.find("servingRatTypes") != info.end()) {
      nlohmann::json servingRatTypes = data["lmfInfo"]["servingRatTypes"];
      for (auto ratType : servingRatTypes) {
        lmf_info.servingRatTypes.push_back(ratType);
      }
    }
  }
  display();
}

//------------------------------------------------------------------------------
void lmf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::lmf_app().info(
      "Handle heartbeart timeout profile %s, time %d", nf_instance_id.c_str(),
      ms);
  set_nf_status("SUSPENDED");
}
