/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "logger.hpp"
#include "pcf_profile.hpp"
#include "string.hpp"

using namespace std;
using namespace oai::pcf::app;
using namespace oai::common::sbi;

//------------------------------------------------------------------------------
void nf_profile::set_nf_instance_id(const std::string& instance_id) {
  nf_instance_id = instance_id;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_instance_id(std::string& instance_id) const {
  instance_id = nf_instance_id;
}

//------------------------------------------------------------------------------
std::string nf_profile::get_nf_instance_id() const {
  return nf_instance_id;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_instance_name(const std::string& instance_name) {
  nf_instance_name = instance_name;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_instance_name(std::string& instance_name) const {
  instance_name = nf_instance_name;
}

//------------------------------------------------------------------------------
std::string nf_profile::get_nf_instance_name() const {
  return nf_instance_name;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_type(const std::string& type) {
  nf_type = type;
}

//------------------------------------------------------------------------------
std::string nf_profile::get_nf_type() const {
  return nf_type;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_status(const std::string& status) {
  nf_status = status;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_status(std::string& status) const {
  status = nf_status;
}

//------------------------------------------------------------------------------
std::string nf_profile::get_nf_status() const {
  return nf_status;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_heartBeat_timer(const int32_t& timer) {
  heartBeat_timer = timer;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_heartBeat_timer(int32_t& timer) const {
  timer = heartBeat_timer;
}

//------------------------------------------------------------------------------
int32_t nf_profile::get_nf_heartBeat_timer() const {
  return heartBeat_timer;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_priority(const uint16_t& p) {
  priority = p;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_priority(uint16_t& p) const {
  p = priority;
}

//------------------------------------------------------------------------------
uint16_t nf_profile::get_nf_priority() const {
  return priority;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_capacity(const uint16_t& c) {
  capacity = c;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_capacity(uint16_t& c) const {
  c = capacity;
}

//------------------------------------------------------------------------------
uint16_t nf_profile::get_nf_capacity() const {
  return capacity;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_snssais(const std::vector<snssai_t>& s) {
  snssais = s;
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_snssais(std::vector<snssai_t>& s) const {
  s = snssais;
}

//------------------------------------------------------------------------------
void nf_profile::add_snssai(const snssai_t& s) {
  snssais.push_back(s);
}

//------------------------------------------------------------------------------
void nf_profile::set_fqdn(const std::string& fqdN) {
  fqdn = fqdN;
}

//------------------------------------------------------------------------------
std::string nf_profile::get_fqdn() const {
  return fqdn;
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_ipv4_addresses(const std::vector<struct in_addr>& a) {
  ipv4_addresses = a;
}

//------------------------------------------------------------------------------
void nf_profile::add_nf_ipv4_addresses(const struct in_addr& a) {
  ipv4_addresses.push_back(a);
}

//------------------------------------------------------------------------------
void nf_profile::set_nf_ipv6_addresses(const std::vector<struct in6_addr>& a) {
  ipv6_addresses = a;
}

//------------------------------------------------------------------------------
void nf_profile::add_nf_ipv6_addresses(const struct in6_addr& a) {
  ipv6_addresses.push_back(a);
}

//------------------------------------------------------------------------------
void nf_profile::get_nf_ipv4_addresses(std::vector<struct in_addr>& a) const {
  a = ipv4_addresses;
}

//------------------------------------------------------------------------------
void nf_profile::display() const {
  Logger::pcf_app().debug("NF instance info");
  Logger::pcf_app().debug("\tInstance ID: %s", nf_instance_id.c_str());

  Logger::pcf_app().debug("\tInstance name: %s", nf_instance_name.c_str());
  Logger::pcf_app().debug("\tInstance type: %s", nf_type.c_str());
  Logger::pcf_app().debug("\tStatus: %s", nf_status.c_str());
  Logger::pcf_app().debug("\tHeartBeat timer: %d", heartBeat_timer);
  Logger::pcf_app().debug("\tPriority: %d", priority);
  Logger::pcf_app().debug("\tCapacity: %d", capacity);
  // SNSSAIs
  if (snssais.size() > 0) {
    Logger::pcf_app().debug("\tSNSSAI:");
  }
  for (auto s : snssais) {
    Logger::pcf_app().debug("\t\t SST %d, SD %d", s.sst, s.sd);
  }
  if (!fqdn.empty()) {
    Logger::pcf_app().debug("\tFQDN: %s", fqdn.c_str());
  }
  // IPv4 Addresses
  if (ipv4_addresses.size() > 0) {
    Logger::pcf_app().debug("\tIPv4 Addr:");
  }
  for (auto address : ipv4_addresses) {
    Logger::pcf_app().debug("\t\t %s", inet_ntoa(address));
  }
  // IPv6 Addresses
  // if (ipv6_addresses.size() > 0) {
  //   Logger::pcf_app().debug("\tIPv6 Addr:");
  // }
  // for (auto address : ipv6_addresses) {
  //   Logger::pcf_app().debug("\t\t %s", inet_ntoa(address));
  // }
}

//------------------------------------------------------------------------------
void nf_profile::to_json(nlohmann::json& data) const {
  data["nfInstanceId"]   = nf_instance_id;
  data["nfInstanceName"] = nf_instance_name;
  data["nfType"]         = nf_type;
  data["nfStatus"]       = nf_status;
  data["heartBeatTimer"] = heartBeat_timer;
  // SNSSAIs
  data["sNssais"] = nlohmann::json::array();
  for (auto s : snssais) {
    nlohmann::json tmp = {};
    tmp["sst"]         = s.sst;
    tmp["sd"]          = s.sd;
    data["sNssais"].push_back(tmp);
  }
  if (!fqdn.empty()) {
    data["fqdn"] = fqdn;
  }
  // ipv4_addresses
  data["ipv4Addresses"] = nlohmann::json::array();
  for (auto address : ipv4_addresses) {
    data["ipv4Addresses"].push_back(inet_ntoa(address));
  }
  // // ipv6_addresses
  // data["ipv6Addresses"] = nlohmann::json::array();
  // for (auto address : ipv6_addresses) {
  //   nlohmann::json tmp = inet_ntoa(address);
  //   data["ipv6Addresses"].push_back(tmp);
  // }
  data["priority"] = priority;
  data["capacity"] = capacity;
}

//------------------------------------------------------------------------------
void nf_profile::from_json(const nlohmann::json& data) {
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
      snssai_t s(it["sst"].get<int>(), it["sd"].get<std::string>());

      snssais.push_back(s);
    }
  }

  if (data.find("fqdn") != data.end()) {
    fqdn = data["fqdn"].get<std::string>();
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
        Logger::pcf_app().warn(
            "Address conversion: Bad value %s",
            oai::utils::trim(address).c_str());
      }
      add_nf_ipv4_addresses(addr4);
    }
  }

  // ToDo: ipv6Addresses

  if (data.find("priority") != data.end()) {
    priority = data["priority"].get<int>();
  }

  if (data.find("capacity") != data.end()) {
    capacity = data["capacity"].get<int>();
  }
}

//------------------------------------------------------------------------------
void pcf_profile::set_nf_services(const std::vector<nf_service_t>& n) {
  nf_services = n;
}

//------------------------------------------------------------------------------
void pcf_profile::add_nf_service(const nf_service_t& n) {
  nf_services.push_back(n);
}

//------------------------------------------------------------------------------
void pcf_profile::get_nf_services(std::vector<nf_service_t>& n) const {
  n = nf_services;
}

//------------------------------------------------------------------------------
void pcf_profile::set_custom_info(const nlohmann::json& c) {
  custom_info = c;
}

//------------------------------------------------------------------------------
void pcf_profile::get_custom_info(nlohmann::json& c) const {
  c = custom_info;
}

//------------------------------------------------------------------------------
void pcf_profile::set_pcf_info(const pcf_info_t& s) {
  pcf_info = s;
}

//------------------------------------------------------------------------------
void pcf_profile::get_pcf_info(pcf_info_t& s) const {
  s = pcf_info;
}

//------------------------------------------------------------------------------
void pcf_profile::display() const {
  Logger::pcf_app().debug("- NF instance info");
  Logger::pcf_app().debug("    Instance ID: %s", nf_instance_id.c_str());
  Logger::pcf_app().debug("    Instance name: %s", nf_instance_name.c_str());
  Logger::pcf_app().debug("    Instance type: %s", nf_type.c_str());
  Logger::pcf_app().debug("    Instance fqdn: %s", fqdn.c_str());
  Logger::pcf_app().debug("    Status: %s", nf_status.c_str());
  Logger::pcf_app().debug("    HeartBeat timer: %d", heartBeat_timer);
  Logger::pcf_app().debug("    Priority: %d", priority);
  Logger::pcf_app().debug("    Capacity: %d", capacity);

  // SNSSAIs
  if (snssais.size() > 0) {
    Logger::pcf_app().debug("    SNSSAI:");
  }
  for (auto s : snssais) {
    Logger::pcf_app().debug(s.to_model_snssai().to_string(4));
  }

  // IPv4 Addresses
  if (ipv4_addresses.size() > 0) {
    Logger::pcf_app().debug("    IPv4 Addr:");
  }
  for (auto address : ipv4_addresses) {
    Logger::pcf_app().debug("        %s", inet_ntoa(address));
  }
  Logger::pcf_app().debug("\tPCF Info");
  Logger::pcf_app().debug("\t\t GroupId: %s", pcf_info.groupid.c_str());
  for (auto supi : pcf_info.supi_ranges) {
    Logger::pcf_app().debug(
        "\t\t SupiRanges: Start - %s, End - %s, Pattern - %s",
        supi.supi_range.start.c_str(), supi.supi_range.end.c_str(),
        supi.supi_range.pattern.c_str());
  }
  for (auto gpsi : pcf_info.gpsi_ranges) {
    Logger::pcf_app().debug(
        "\t\t GpsiRanges: Start - %s, End - %s, Pattern - %s",
        gpsi.identity_range.start.c_str(), gpsi.identity_range.end.c_str(),
        gpsi.identity_range.pattern.c_str());
  }
  for (auto dnn : pcf_info.dnn_list) {
    Logger::pcf_app().debug("\t\t DNN: %s", dnn.c_str());
  }
}

//------------------------------------------------------------------------------
void pcf_profile::to_json(nlohmann::json& data) const {
  nf_profile::to_json(data);

  // NF services
  data["nfServices"] = nlohmann::json::array();
  for (auto service : nf_services) {
    nlohmann::json srv_tmp       = {};
    srv_tmp["serviceInstanceId"] = service.service_instance_id;
    srv_tmp["serviceName"]       = service.service_name;
    srv_tmp["versions"]          = nlohmann::json::array();
    for (auto const& v : service.versions) {
      nlohmann::json v_tmp     = {};
      v_tmp["apiVersionInUri"] = v.api_version_in_uri;
      v_tmp["apiFullVersion"]  = v.api_full_version;
      srv_tmp["versions"].push_back(v_tmp);
    }
    srv_tmp["scheme"]          = service.scheme;
    srv_tmp["nfServiceStatus"] = service.nf_service_status;
    // IP endpoints
    srv_tmp["ipEndPoints"] = nlohmann::json::array();
    for (auto endpoint : service.ip_endpoints) {
      nlohmann::json ep_tmp = {};
      ep_tmp["ipv4Address"] = inet_ntoa(endpoint.ipv4_address);
      ep_tmp["transport"]   = endpoint.transport;
      ep_tmp["port"]        = endpoint.port;
      srv_tmp["ipEndPoints"].push_back(ep_tmp);
    }

    data["nfServices"].push_back(srv_tmp);
  }

  data["custom_info"] = custom_info;

  // PCF info
  data["pcfInfo"]["groupId"]    = pcf_info.groupid;
  data["pcfInfo"]["dnnList"]    = nlohmann::json::array();
  data["pcfInfo"]["supiRanges"] = nlohmann::json::array();
  data["pcfInfo"]["gpsiRanges"] = nlohmann::json::array();

  for (auto supi : pcf_info.supi_ranges) {
    nlohmann::json tmp = {};
    tmp["start"]       = supi.supi_range.start;
    tmp["end"]         = supi.supi_range.end;
    tmp["pattern"]     = supi.supi_range.pattern;
    data["pcfInfo"]["supiRanges"].push_back(tmp);
  }
  for (auto gpsi : pcf_info.gpsi_ranges) {
    nlohmann::json tmp = {};
    tmp["start"]       = gpsi.identity_range.start;
    tmp["end"]         = gpsi.identity_range.end;
    tmp["pattern"]     = gpsi.identity_range.pattern;
    data["pcfInfo"]["gpsiRanges"].push_back(tmp);
  }
  for (auto dnn : pcf_info.dnn_list) {
    data["pcfInfo"]["dnnList"].push_back(dnn);
  }

  Logger::pcf_app().debug("PCF profile to json:\n %s", data.dump().c_str());
}

//------------------------------------------------------------------------------
void pcf_profile::from_json(const nlohmann::json& data) {
  nf_profile::from_json(data);

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
      snssai_t s(it["sst"].get<int>(), it["sd"].get<std::string>());
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
        Logger::pcf_app().warn(
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
  // PCF info
  if (data.find("pcfInfo") != data.end()) {
    nlohmann::json info = data["pcfInfo"];
    if (info.find("groupId") != info.end()) {
      pcf_info.groupid = info["groupId"].get<std::string>();
    }
    if (info.find("dnnList") != info.end()) {
      nlohmann::json dnnList = data["pcfInfo"]["dnnList"];
      for (auto d : dnnList) {
        pcf_info.dnn_list.push_back(d);
      }
    }
    if (info.find("supiRanges") != info.end()) {
      nlohmann::json supi_ranges = data["pcfInfo"]["supiRanges"];
      for (auto d : supi_ranges) {
        supi_range_info_item_t supi;
        supi.supi_range.start   = d["start"];
        supi.supi_range.end     = d["end"];
        supi.supi_range.pattern = d["pattern"];
        pcf_info.supi_ranges.push_back(supi);
      }
    }
    if (info.find("gpsiRanges") != info.end()) {
      nlohmann::json gpsi_ranges = data["pcfInfo"]["gpsiRanges"];
      for (auto d : gpsi_ranges) {
        identity_range_info_item_t gpsi;
        gpsi.identity_range.start   = d["start"];
        gpsi.identity_range.end     = d["end"];
        gpsi.identity_range.pattern = d["pattern"];
        pcf_info.gpsi_ranges.push_back(gpsi);
      }

      // TODO: custom_info;
    }
  }

  display();
}

//------------------------------------------------------------------------------
void pcf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::pcf_app().info(
      "Handle heartbeart timeout profile %s, time %d", nf_instance_id.c_str(),
      ms);
  set_nf_status("SUSPENDED");
}
