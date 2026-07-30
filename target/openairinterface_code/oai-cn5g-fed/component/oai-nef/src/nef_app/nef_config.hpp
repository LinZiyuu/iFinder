/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NEF_CONFIG_HPP_SEEN
#define FILE_NEF_CONFIG_HPP_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <libconfig.h++>
#include <mutex>
#include <vector>

#define NEF_CONFIG_STRING_NEF_CONFIG "NEF"
#define NEF_CONFIG_STRING_PID_DIRECTORY "PID_DIRECTORY"
#define NEF_CONFIG_STRING_INSTANCE "INSTANCE"
#define NEF_CONFIG_STRING_INTERFACE_SBI "SBI_INTERFACE"
#define NEF_CONFIG_STRING_INTERFACE_NAME "INTERFACE_NAME"
#define NEF_CONFIG_STRING_IPV4_ADDRESS "IPV4_ADDRESS"
#define NEF_CONFIG_STRING_PORT "PORT"
#define NEF_CONFIG_STRING_SBI_HTTP2_PORT "HTTP2_PORT"
#define NEF_CONFIG_STRING_API_VERSION "API_VERSION"
#define NEF_CONFIG_STRING_FQDN_DNS "FQDN"

#define NEF_CONFIG_STRING_AMF "AMF"
#define NEF_CONFIG_STRING_SMF "SMF"
#define NEF_CONFIG_STRING_UDM "UDM"

#define NEF_CONFIG_STRING_SUPPORT_FEATURES "SUPPORT_FEATURES"
#define NEF_CONFIG_STRING_SUPPORT_FEATURES_USE_FQDN_DNS "USE_FQDN_DNS"
#define NEF_CONFIG_STRING_SUPPORT_FEATURES_USE_HTTP2 "USE_HTTP2"

namespace oai::nef::app {
using namespace libconfig;
typedef struct interface_cfg_s {
  std::string if_name;
  struct in_addr addr4;
  struct in_addr network4;
  struct in6_addr addr6;
  unsigned int mtu;
  unsigned int port;
  unsigned int http2_port;
  std::string api_version;
} interface_cfg_t;

typedef struct nf_addr_s {
  struct in_addr ipv4_addr;
  unsigned int port;
  unsigned int http2_port;
  std::string api_version;
  std::string fqdn;
} nf_addr_t;

class nef_config {
 private:
  int load_interface(const libconfig::Setting& if_cfg, interface_cfg_t& cfg);
  void load_nf_info(const Setting& nf_cfg, nf_addr_t& nf_addr);

 public:
  /* Reader/writer lock for this configuration */
  std::mutex m_rw_lock;
  std::string pid_dir;
  unsigned int instance = 0;

  interface_cfg_t sbi;
  nf_addr_t amf_addr;
  nf_addr_t smf_addr;
  nf_addr_t udm_addr;

  struct {
    bool use_fqdn_dns;
    bool use_http2;
  } support_features;

  nef_config();
  virtual ~nef_config();
  void lock() { m_rw_lock.lock(); };
  void unlock() { m_rw_lock.unlock(); };
  int load(const std::string& config_file);
  void display();

  std::string get_event_exposure_url();
  std::string get_event_exposure_subscription_url();
  // NEF endpoint which will be use to receive the notification (change) from
  // AMF/SMF
  std::string get_event_exposure_subscription_notify_url();
  std::string get_amf_event_exposure_url();
};

}  // namespace oai::nef::app
#endif /* FILE_NEF_CONFIG_HPP_SEEN */
