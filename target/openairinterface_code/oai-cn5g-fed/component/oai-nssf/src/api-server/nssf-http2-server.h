/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NSSF_HTTP2_SERVER_SEEN
#define FILE_NSSF_HTTP2_SERVER_SEEN

#include <nghttp2/asio_http2_server.h>

#include "NFInstanceIDDocumentApiImpl.h"
#include "NSSAIAvailabilityStoreApiImpl.h"
#include "NetworkSliceInformationDocumentApiImpl.h"
#include "SubscriptionIDDocumentApiImpl.h"
#include "SubscriptionsCollectionApiImpl.h"
#include "conversions.hpp"
#include "nssf.h"
#include "nssf_app.hpp"
#include "string.hpp"
#include "uint_generator.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::nssf_server::model;

class nssf_http2_server {
 public:
  nssf_http2_server(
      std::string addr, uint32_t port, nssf::nssf_app* nssf_app_inst)
      : m_address(addr), m_port(port), server(), m_nssf_app(nssf_app_inst) {}
  void start();
  void init(size_t thr) {}

  // NSSF NS Selection - Network Slice Information (Document)
  void get_slice_info_for_registration_handler(
      const std::string& nf_type, std::string& nf_id,
      const SliceInfoForRegistration slice_info,
      const oai::model::common::Tai& tai,
      const oai::model::common::PlmnId& home_plmnid,
      const std::string& features, const response& response);

  void get_slice_info_for_pdu_session_handler(
      const std::string& nf_type, std::string& nf_id,
      const SliceInfoForPDUSession& slice_info,
      const oai::model::common::Tai& tai,
      const oai::model::common::PlmnId& home_plmnid,
      const std::string& features, const response& response);

  void get_slice_info_for_ue_cu_handler(
      const std::string& nf_type, std::string& nf_id,
      const SliceInfoForUEConfigurationUpdate& slice_info,
      const oai::model::common::Tai& tai,
      const oai::model::common::PlmnId& home_plmnid,
      const std::string& features, const response& response);

  void get_slice_info_default_handler(
      const std::string& nf_type, std::string& nf_id,
      const oai::model::common::Tai& tai,
      const oai::model::common::PlmnId& home_plmnid,
      const std::string& features, const response& response);

  // NSSF NSSAI Availability - NF Instance ID (Document)
  void create_nssai_availability_handler(
      const std::string& nfId, const NssaiAvailabilityInfo& nssaiAvailInfo,
      const response& response);

  void update_n_ssai_availability_handler(
      const std::string& nfId,
      const std::vector<oai::model::common::PatchItem>& patchItem,
      const response& response);

  void remove_n_ssai_availability_handler(
      const std::string& nfId, const response& response);

  // NSSF NSSAI Availability - Subscription ID (Collection/Document)
  void create_subscription_n_ssai_availability_handler(
      const NssfEventSubscriptionCreateData& subscriptionData,
      const response& response);

  void update_subscription_n_ssai_availability_handler(
      const NssfEventSubscriptionCreateData& subscriptionData,
      const response& response);

  void remove_subscription_n_ssai_availability_handler(
      const std::string& subscriptionId, const response& response);

  // NSSF Custom API to get slice config
  void get_slice_config(const response& response);
  // void get_current_slice_config(const response &response);
  void get_api_list(const response& response);

  void stop();

 private:
  oai::utils::uint_generator<uint32_t> m_promise_id_generator;
  std::string m_address;
  uint32_t m_port;
  http2 server;
  nssf::nssf_app* m_nssf_app;
  bool running_server;
};

#endif
