/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf-http2-server.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>

#include "3gpp_29.500.h"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "api_defs.h"
#include "SmPolicyContextData.h"
#include "AppSessionContext.h"
#include "PcscfRestorationRequestData.h"
#include "EventsSubscReqData.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "PccRule.h"
#include "QosData.h"
#include "TrafficControlData.h"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::config::pcf;
using namespace oai::pcf::api;
using namespace oai::common::sbi;

extern std::unique_ptr<pcf_config> pcf_cfg;

//------------------------------------------------------------------------------
void pcf_http2_server::start() {
  boost::system::error_code ec;

  Logger::pcf_sbi().info("HTTP2 server being started");
  std::string nfId           = {};
  std::string subscriptionID = {};

  // SM Policies Collection API
  server.handle(
      sm_policies::get_route(),
      [&](const request& request, const response& response) {
        if (request.method() != "POST") {
          handle_method_not_exists(response, request);
          return;
        }
        auto request_body = std::make_shared<std::stringstream>();

        request.on_data(
            [&, request_body](const uint8_t* data, std::size_t len) {
              if (len > 0) {
                std::copy(
                    data, data + len,
                    std::ostream_iterator<uint8_t>(*request_body));
                return;
              }
              SmPolicyContextData context;
              try {
                Logger::pcf_sbi().error(
                    "SM Policies request body: %s", request_body->str());
                nlohmann::json::parse(request_body->str()).get_to(context);
                context.validate();
                api_response resp =
                    m_collection_api_handler->create_sm_policy(context);
                auto h_map = convert_headers(resp);
                response.write_head(
                    static_cast<unsigned int>(resp.status_code), h_map);
                response.end(resp.body);
                return;
              } catch (std::exception& e) {
                handle_parsing_error(response, e);
                return;
              }
            });
      });

  // Individual SM Policy
  // We match for sm-policies/*
  server.handle(
      sm_policies::get_route() + "/",
      [&](const request& request, const response& response) {
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        bool is_update = false;
        bool is_delete = false;
        bool is_get    = false;
        std::string policy_id;
        if (split_result[split_result.size() - 1] == "delete") {
          is_delete = true;
          policy_id = split_result[split_result.size() - 2];
        } else if (split_result[split_result.size() - 1] == "update") {
          is_update = true;
          policy_id = split_result[split_result.size() - 2];
        } else {
          is_get    = true;
          policy_id = split_result[split_result.size() - 1];
        }
        if ((is_delete || is_update) && request.method() != "POST") {
          handle_method_not_exists(response, request);
          return;
        }
        if (is_get && request.method() != "GET") {
          handle_method_not_exists(response, request);
          return;
        }
        auto request_body = std::make_shared<std::stringstream>();

        request.on_data([&, request_body, is_get, is_update, is_delete,
                         policy_id](const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::copy(
                data, data + len,
                std::ostream_iterator<uint8_t>(*request_body));
            return;
          }
          SmPolicyDeleteData delete_data;
          SmPolicyUpdateContextData update_context_data;
          api_response resp;
          try {
            if (is_update) {
              nlohmann::json::parse(request_body->str())
                  .get_to(update_context_data);
              update_context_data.validate();
              resp = m_individual_api_handler->update_sm_policy(
                  policy_id, update_context_data);
            } else if (is_delete) {
              nlohmann::json::parse(request_body->str()).get_to(delete_data);
              delete_data.validate();
              resp = m_individual_api_handler->delete_sm_policy(
                  policy_id, delete_data);
            } else if (is_get) {
              resp = m_individual_api_handler->get_sm_policy(policy_id);
            }
            auto h_map = convert_headers(resp);
            response.write_head(
                static_cast<unsigned int>(resp.status_code), h_map);
            response.end(resp.body);
            return;
          } catch (std::exception& e) {
            handle_parsing_error(response, e);
            return;
          }
        });
      });

  // Watch for /app-sessions
  server.handle(
      app_sessions::get_route(),
      [&](const request& request, const response& response) {
        if (request.method() != "POST") {
          handle_method_not_exists(response, request);
          return;
        }
        auto request_body = std::make_shared<std::stringstream>();

        request.on_data([&, request_body](
                            const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::copy(
                data, data + len,
                std::ostream_iterator<uint8_t>(*request_body));
            return;
          }
          AppSessionContext context;
          try {
            nlohmann::json::parse(request_body->str()).get_to(context);
            context.validate();
            api_response resp = m_application_sessions_collection_api_handler
                                    ->post_app_sessions(context);
            auto h_map = convert_headers(resp);
            response.write_head(
                static_cast<unsigned int>(resp.status_code), h_map);
            response.end(resp.body);
            return;
          } catch (std::exception& e) {
            handle_parsing_error(response, e);
            return;
          }
        });
      });

  // We match for /app-sessions/pcsfc-restoration
  server.handle(
      app_sessions::get_route(),
      [&](const request& request, const response& response) {
        if (request.method() != "POST") {
          handle_method_not_exists(response, request);
          return;
        }
        auto request_body = std::make_shared<std::stringstream>();

        request.on_data([&, request_body](
                            const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::copy(
                data, data + len,
                std::ostream_iterator<uint8_t>(*request_body));
            return;
          }
          PcscfRestorationRequestData pcscf_restoration_data;
          try {
            nlohmann::json::parse(request_body->str())
                .get_to(pcscf_restoration_data);
            pcscf_restoration_data.validate();
            api_response resp =
                m_pcscf_restoration_indication_api_handler->pcscf_restoration(
                    pcscf_restoration_data);
            auto h_map = convert_headers(resp);
            response.write_head(
                static_cast<unsigned int>(resp.status_code), h_map);
            response.end(resp.body);
            return;
          } catch (std::exception& e) {
            handle_parsing_error(response, e);
            return;
          }
        });
      });

  // We match for /app-sessions/*
  server.handle(
      app_sessions::get_route() + "/",
      [&](const request& request, const response& response) {
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        bool is_get_patch = false;  // /app-sessions/{appSessionId}
        bool is_delete    = false;  // /app-sessions/{appSessionId}/delete
        bool is_event =
            false;  // /app-sessions/{appSessionId}/events-subscription

        std::string app_session_id;
        if (split_result[split_result.size() - 1] == "delete") {
          is_delete      = true;
          app_session_id = split_result[split_result.size() - 2];
        } else if (
            split_result[split_result.size() - 1] == "events-subscription") {
          is_event       = true;
          app_session_id = split_result[split_result.size() - 2];
        } else {
          is_get_patch   = true;
          app_session_id = split_result[split_result.size() - 1];
        }

        if (is_event &&
            (request.method() != "PUT" && request.method() != "DELETE")) {
          handle_method_not_exists(response, request);
          return;
        }

        if (is_get_patch &&
            (request.method() != "GET" && request.method() != "PATCH")) {
          handle_method_not_exists(response, request);
          return;
        }

        auto request_body = std::make_shared<std::stringstream>();

        request.on_data([&, request_body, is_get_patch, is_delete, is_event,
                         app_session_id](const uint8_t* data, std::size_t len) {
          if (len > 0) {
            std::copy(
                data, data + len,
                std::ostream_iterator<uint8_t>(*request_body));
            return;
          }
          EventsSubscReqData events_subsc_data;
          AppSessionContextUpdateDataPatch app_session_context_data;
          api_response resp;
          try {
            if (is_delete) {
              nlohmann::json::parse(request_body->str())
                  .get_to(events_subsc_data);
              events_subsc_data.validate();
              resp =
                  m_individual_application_session_context_document_api_handler
                      ->delete_app_session(app_session_id, events_subsc_data);
            } else if (is_event && request.method() == "PUT") {
              nlohmann::json::parse(request_body->str())
                  .get_to(events_subsc_data);
              events_subsc_data.validate();
              resp =
                  m_events_subscription_document_api_handler
                      ->update_events_subsc(app_session_id, events_subsc_data);
            } else if (is_event && request.method() == "DELTE") {
              resp = m_events_subscription_document_api_handler
                         ->delete_events_subsc(app_session_id);
            } else if (is_get_patch && request.method() == "GET") {
              resp =
                  m_individual_application_session_context_document_api_handler
                      ->get_app_session(app_session_id);
            } else if (is_get_patch && request.method() == "PATCH") {
              nlohmann::json::parse(request_body->str())
                  .get_to(app_session_context_data);
              Logger::pcf_sbi().info("App Session Context Update Data:");
              app_session_context_data.validate();
              resp =
                  m_individual_application_session_context_document_api_handler
                      ->mod_app_session(
                          app_session_id, app_session_context_data);
            }
            auto h_map = convert_headers(resp);
            response.write_head(
                static_cast<unsigned int>(resp.status_code), h_map);
            response.end(resp.body);
            return;
          } catch (std::exception& e) {
            handle_parsing_error(response, e);
            return;
          }
        });
      });
  /*******************************************************
   *           Policy Decision Provisioning API
   *******************************************************/

  auto provisioning_base =
      policy_decision_provisioning::get_provisioning_base();

  // Default Policy API
  server.handle(
      provisioning_base + "/defaultDecision",
      [&](const request& request, const response& response) {
        if (request.method() == "GET") {
          api_response resp =
              m_default_policy_decisions_handler->default_decision_get();
          send_response(response, resp);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data(
              [&, request_body](const uint8_t* data, std::size_t len) {
                if (len > 0) {
                  std::copy(
                      data, data + len,
                      std::ostream_iterator<uint8_t>(*request_body));
                  return;
                }
                try {
                  std::vector<std::string> pccRules;
                  nlohmann::json::parse(request_body->str()).get_to(pccRules);
                  api_response resp =
                      m_default_policy_decisions_handler->default_decision_put(
                          pccRules);
                  send_response(response, resp);
                  return;
                } catch (std::exception& e) {
                  handle_parsing_error(response, e);
                  return;
                }
              });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  /**
   *  DNN Policy Decision
   */
  server.handle(
      provisioning_base + "/dnnPolicyDecision",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              oai::pcf::provisioning::model::DnnPolicyDecision dnnDecision;
              nlohmann::json::parse(request_body->str()).get_to(dnnDecision);
              api_response resp =
                  m_dnn_policy_decisions_handler->dnn_policy_decision_post(
                      dnnDecision);
              send_response(response, resp);
              return;

            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  server.handle(
      provisioning_base + "/dnnPolicyDecision/",
      [&](const request& request, const response& response) {
        api_response resp;
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        std::string dnn;
        dnn = split_result[split_result.size() - 1];
        if (request.method() == "GET") {
          resp =
              m_dnn_policy_decisions_handler->dnn_policy_decision_dnn_get(dnn);
        } else if (request.method() == "DELETE") {
          resp = m_dnn_policy_decisions_handler->dnn_policy_decision_dnn_delete(
              dnn);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body, dnn](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              oai::pcf::provisioning::model::DnnPolicyDecision dnnDecision;
              nlohmann::json::parse(request_body->str()).get_to(dnnDecision);
              api_response put_resp =
                  m_dnn_policy_decisions_handler->dnn_policy_decision_dnn_put(
                      dnn, dnnDecision);
              send_response(response, put_resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
        send_response(response, resp);
        return;
      });

  server.handle(
      provisioning_base + "/dnnPolicyDecisions",
      [&](const request& request, const response& response) {
        if (request.method() == "GET") {
          api_response resp =
              m_dnn_policy_decisions_handler->dnn_policy_decisions_get();
          send_response(response, resp);
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  /**
   *  Slice Policy Decision
   */
  server.handle(
      provisioning_base + "/slicePolicyDecision",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              oai::pcf::provisioning::model::SlicePolicyDecision sliceDecision;
              nlohmann::json::parse(request_body->str()).get_to(sliceDecision);
              api_response resp =
                  m_slice_policy_decisions_handler->slice_policy_decision_post(
                      sliceDecision);
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          std::string query = request.uri().raw_query;
          // Parse query parameters sst and sd
          auto query_params = parse_query(query);

          // Initialize variables to hold the expected parameters
          int32_t sst = 0;
          std::string sd;

          // Check and parse the 'sst' parameter
          if (query_params.find("sst") != query_params.end()) {
            try {
              sst = std::stoi(query_params["sst"]);
            } catch (const std::exception& e) {
              std::cerr << "Error parsing 'sst': " << e.what() << std::endl;
              response.write_head(400);
              response.end("Invalid 'sst' parameter");
              return;
            }
          } else {
            response.write_head(400);
            response.end("Missing 'sst' parameter");
            return;
          }

          // Check and parse the 'sd' parameter
          if (query_params.find("sd") != query_params.end()) {
            sd = query_params["sd"];
          } else {
            sd = oai::model::common::SD_DEFAULT_VALUE;
          }
          api_response resp;
          // slice = split_result[split_result.size() - 1];
          if (request.method() == "GET") {
            resp = m_slice_policy_decisions_handler->slice_policy_decision_get(
                sst, sd);
          } else if (request.method() == "DELETE") {
            resp =
                m_slice_policy_decisions_handler->slice_policy_decision_delete(
                    sst, sd);
          } else if (request.method() == "PUT") {
            auto request_body = std::make_shared<std::stringstream>();
            request.on_data([&, request_body, sst, sd](
                                const uint8_t* data, std::size_t len) {
              if (len > 0) {
                std::copy(
                    data, data + len,
                    std::ostream_iterator<uint8_t>(*request_body));
                return;
              }
              try {
                oai::pcf::provisioning::model::SlicePolicyDecision
                    sliceDecision;
                nlohmann::json::parse(request_body->str())
                    .get_to(sliceDecision);
                api_response put_resp =
                    m_slice_policy_decisions_handler->slice_policy_decision_put(
                        sst, sd, sliceDecision);
                send_response(response, put_resp);
                return;
              } catch (std::exception& e) {
                handle_parsing_error(response, e);
                return;
              }
            });
            return;
          } else {
            handle_method_not_exists(response, request);
            return;
          }
          send_response(response, resp);
          return;
        }
      });

  server.handle(
      provisioning_base + "/slicePolicyDecisions",
      [&](const request& request, const response& response) {
        api_response resp;
        if (request.method() == "GET") {
          resp = m_slice_policy_decisions_handler->slice_policy_decisions_get();
        } else {
          handle_method_not_exists(response, request);
          return;
        }
        send_response(response, resp);
        return;
      });

  /**
   *  Supi Policy Decision
   */
  server.handle(
      provisioning_base + "/supiPolicyDecision",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            oai::pcf::provisioning::model::SupiPolicyDecision supiDecision;
            try {
              nlohmann::json::parse(request_body->str()).get_to(supiDecision);
              supiDecision.validate();
              api_response resp =
                  m_supi_policy_decisions_handler->supi_policy_decision_post(
                      supiDecision);
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  server.handle(
      provisioning_base + "/supiPolicyDecision/",
      [&](const request& request, const response& response) {
        api_response resp;
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        std::string supi;
        supi = split_result[split_result.size() - 1];
        if (request.method() == "GET") {
          resp = m_supi_policy_decisions_handler->supi_policy_decision_supi_get(
              supi);
        } else if (request.method() == "DELETE") {
          resp =
              m_supi_policy_decisions_handler->supi_policy_decision_supi_delete(
                  supi);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body, supi](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              oai::pcf::provisioning::model::SupiPolicyDecision supiDecision;
              nlohmann::json::parse(request_body->str()).get_to(supiDecision);
              api_response put_resp =
                  m_supi_policy_decisions_handler
                      ->supi_policy_decision_supi_put(supi, supiDecision);
              send_response(response, put_resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }

        send_response(response, resp);
        return;
      });

  server.handle(
      provisioning_base + "/supiPolicyDecisions",
      [&](const request& request, const response& response) {
        if (request.method() == "GET") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              api_response resp =
                  m_supi_policy_decisions_handler->supi_policy_decisions_get();
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  /**
   *  PCC Rules
   */
  server.handle(
      provisioning_base + "/pccRule",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              PccRule pccRule;
              nlohmann::json::parse(request_body->str()).get_to(pccRule);
              api_response resp = m_pcc_rules_handler->pcc_rule_post(pccRule);
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  server.handle(
      provisioning_base + "/pccRule/",
      [&](const request& request, const response& response) {
        api_response resp;
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        std::string pccRuleId;
        pccRuleId = split_result[split_result.size() - 1];
        if (request.method() == "GET") {
          resp = m_pcc_rules_handler->pcc_rule_pcc_rule_id_get(pccRuleId);
        } else if (request.method() == "DELETE") {
          resp = m_pcc_rules_handler->pcc_rule_pcc_rule_id_delete(pccRuleId);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body, pccRuleId](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              PccRule pccRule;
              nlohmann::json::parse(request_body->str()).get_to(pccRule);
              api_response put_resp =
                  m_pcc_rules_handler->pcc_rule_pcc_rule_id_put(
                      pccRuleId, pccRule);
              send_response(response, put_resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
        send_response(response, resp);
        return;
      });

  server.handle(
      provisioning_base + "/pccRules",
      [&](const request& request, const response& response) {
        if (request.method() == "GET") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data(
              [&, request_body](const uint8_t* data, std::size_t len) {
                if (len > 0) {
                  std::copy(
                      data, data + len,
                      std::ostream_iterator<uint8_t>(*request_body));
                  return;
                }
                try {
                  api_response resp = m_pcc_rules_handler->pcc_rules_get();
                  send_response(response, resp);
                  return;
                } catch (std::exception& e) {
                  handle_parsing_error(response, e);
                  return;
                }
              });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  /**
   *  Qos Data
   */
  server.handle(
      provisioning_base + "/qosData",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              QosData qosData;
              nlohmann::json::parse(request_body->str()).get_to(qosData);
              api_response resp = m_qos_data_handler->qos_data_post(qosData);
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else if (request.method() == "GET") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data(
              [&, request_body](const uint8_t* data, std::size_t len) {
                if (len > 0) {
                  std::copy(
                      data, data + len,
                      std::ostream_iterator<uint8_t>(*request_body));
                  return;
                }
                try {
                  api_response resp = m_qos_data_handler->qos_data_get();
                  send_response(response, resp);
                  return;
                } catch (std::exception& e) {
                  handle_parsing_error(response, e);
                  return;
                }
              });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  server.handle(
      provisioning_base + "/qosData/",
      [&](const request& request, const response& response) {
        api_response resp;
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        std::string qosDataId;
        qosDataId = split_result[split_result.size() - 1];
        if (request.method() == "GET") {
          resp = m_qos_data_handler->qos_data_qos_id_get(qosDataId);
        } else if (request.method() == "DELETE") {
          resp = m_qos_data_handler->qos_data_qos_id_delete(qosDataId);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body, qosDataId](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              QosData qosData;
              nlohmann::json::parse(request_body->str()).get_to(qosData);
              api_response put_resp =
                  m_qos_data_handler->qos_data_qos_id_put(qosDataId, qosData);
              send_response(response, put_resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
        send_response(response, resp);
        return;
      });

  /**
   *  Traffic Control Data
   */
  server.handle(
      provisioning_base + "/trafficControlData",
      [&](const request& request, const response& response) {
        if (request.method() == "POST") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data(
              [&, request_body](const uint8_t* data, std::size_t len) {
                if (len > 0) {
                  std::copy(
                      data, data + len,
                      std::ostream_iterator<uint8_t>(*request_body));
                  return;
                }
                try {
                  TrafficControlData trafficControlData;
                  nlohmann::json::parse(request_body->str())
                      .get_to(trafficControlData);
                  api_response resp =
                      m_traffic_control_data_handler->traffic_control_data_post(
                          trafficControlData);
                  send_response(response, resp);
                  return;
                } catch (std::exception& e) {
                  handle_parsing_error(response, e);
                  return;
                }
              });
        } else if (request.method() == "GET") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              api_response resp =
                  m_traffic_control_data_handler->traffic_control_data_get();
              send_response(response, resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
        } else {
          handle_method_not_exists(response, request);
          return;
        }
      });

  server.handle(
      provisioning_base + "/trafficControlData/",
      [&](const request& request, const response& response) {
        api_response resp;
        std::vector<std::string> split_result;
        boost::split(split_result, request.uri().path, boost::is_any_of("/"));
        std::string trafficControlId;
        trafficControlId = split_result[split_result.size() - 1];
        if (request.method() == "GET") {
          resp = m_traffic_control_data_handler->traffic_control_data_tc_id_get(
              trafficControlId);
        } else if (request.method() == "DELETE") {
          resp =
              m_traffic_control_data_handler->traffic_control_data_tc_id_delete(
                  trafficControlId);
        } else if (request.method() == "PUT") {
          auto request_body = std::make_shared<std::stringstream>();
          request.on_data([&, request_body, trafficControlId](
                              const uint8_t* data, std::size_t len) {
            if (len > 0) {
              std::copy(
                  data, data + len,
                  std::ostream_iterator<uint8_t>(*request_body));
              return;
            }
            try {
              TrafficControlData trafficControlData;
              nlohmann::json::parse(request_body->str())
                  .get_to(trafficControlData);
              api_response put_resp =
                  m_traffic_control_data_handler
                      ->traffic_control_data_tc_id_put(
                          trafficControlId, trafficControlData);
              send_response(response, put_resp);
              return;
            } catch (std::exception& e) {
              handle_parsing_error(response, e);
              return;
            }
          });
          return;
        } else {
          handle_method_not_exists(response, request);
          return;
        }
        send_response(response, resp);
        return;
      });

  // Default Route
  server.handle("/", [&](const request& request, const response& response) {
    handle_method_not_exists(response, request);
    return;
  });

  running_server = true;
  if (server.listen_and_serve(ec, m_address, std::to_string(m_port))) {
    Logger::pcf_sbi().error("HTTP Server error: %s", ec.message());
  }
  running_server = false;
  Logger::pcf_sbi().info("HTTP2 server fully stopped");
}

void pcf_http2_server::stop() {
  server.stop();
  while (running_server) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  Logger::pcf_sbi().info("HTTP2 server should be fully stopped");
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

void pcf_http2_server::handle_method_not_exists(
    const response& response, const request& request) {
  Logger::pcf_sbi().warn(
      "Invalid route/method called: %s : %s", request.method(),
      request.uri().path);
  response.write_head(static_cast<unsigned int>(http_status_code::NOT_FOUND));
  response.end("The requested method does not exist");
}

void pcf_http2_server::handle_parsing_error(
    const response& response, const std::exception& ex) {
  Logger::pcf_sbi().warn("Parsing error: %s", ex.what());
  response.write_head(static_cast<unsigned int>(http_status_code::BAD_REQUEST));
  // for security reasons it is better to not give the internal exception to the
  // user, we can also decide to change that
  response.end("Could not parse JSON data");
}

header_map pcf_http2_server::convert_headers(const api_response& response) {
  header_map h_map;
  for (const auto& hdr : response.headers.list()) {
    std::stringstream ss;
    hdr->write(ss);
    h_map.emplace(hdr->name(), header_value{ss.str(), false});
  }
  return h_map;
}

std::map<std::string, std::string> pcf_http2_server::parse_query(
    const std::string& query) {
  std::map<std::string, std::string> query_map;
  std::string::size_type start = 0;
  std::string::size_type end   = 0;

  while ((end = query.find('&', start)) != std::string::npos) {
    std::string key_value            = query.substr(start, end - start);
    std::string::size_type delimiter = key_value.find('=');

    if (delimiter != std::string::npos) {
      std::string key   = key_value.substr(0, delimiter);
      std::string value = key_value.substr(delimiter + 1);
      query_map[key]    = value;
    }

    start = end + 1;
  }

  // Handle the last key-value pair
  std::string key_value            = query.substr(start);
  std::string::size_type delimiter = key_value.find('=');
  if (delimiter != std::string::npos) {
    std::string key   = key_value.substr(0, delimiter);
    std::string value = key_value.substr(delimiter + 1);
    query_map[key]    = value;
  }

  return query_map;
}
