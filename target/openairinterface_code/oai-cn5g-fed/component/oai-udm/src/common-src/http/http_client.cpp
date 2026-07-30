/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "http_client.hpp"

#include "cpr/ssl_ctx.h"
#include "cpr/ssl_options.h"

#include <nlohmann/json.hpp>

namespace json = nlohmann;
using namespace oai::http;

//---------------------------------------------------------------------------------------------
http_client::http_client(
    oai::logger::printf_logger logger, int timeout_ms,
    const std::string& interface, uint8_t http_version, bool enable_tls,
    request_type_e request_type)
    : m_sbi_logger(std::move(logger)) {
  m_http_version    = http_version;
  m_timeout_ms      = timeout_ms;
  m_interface       = interface;
  m_enable_tls      = enable_tls;
  m_request_type    = request_type;
  m_public_key_path = std::nullopt;

  m_sbi_logger.info(
      "HTTP Client successfully initiated on interface %s with timeout "
      "%ld ms, HTTP version %d",
      m_interface, m_timeout_ms, m_http_version);
}

//---------------------------------------------------------------------------------------------
http_client::~http_client() {
  m_sbi_logger.info("Delete HTTP client instance");
}

//---------------------------------------------------------------------------------------------
std::shared_ptr<http_client> http_client::create_instance(
    const oai::logger::printf_logger& logger, int timeout_ms,
    const std::string& interface, uint8_t http_version, bool enable_tls,
    request_type_e request_type) {
  // If instance does not exits, create a new one
  if (!instance) {
    instance = std::make_shared<http_client>(
        logger, timeout_ms, interface, http_version, enable_tls, request_type);
    return instance;
  }
  // otherwise return the existing one
  return instance;
}

//---------------------------------------------------------------------------------------------
response http_client::send_http_request(
    const method_e& method, const request& request) {
  switch (m_request_type) {
    case request_type_e::ASYNC: {
      auto resp = send_async_http_request(method, request);
      return resp;
    } break;
    case request_type_e::MULTI_ASYNC: {
      // TODO:Use simple HTTP request for the moment
    } break;

    case request_type_e::MULTI_PERFORM: {
      // TODO: Should declare a MultiPerform as a class member so that we can
      // actually support multiple sessions per MultiPerform (causing issue when
      // using multi-threading, similar issue with Curl Multi Interface)
      std::shared_ptr<cpr::MultiPerform> multi_perform =
          std::make_shared<cpr::MultiPerform>();
      add_session_to_multi_peform(method, request, multi_perform);
      auto resp = send_multi_peform_http_request(multi_perform);
      return resp[0];
    } break;
    case request_type_e::SIMPLE:
    default: {  // Use simple HTTP request
    }
  };

  // By default using a simple HTTP request
  auto resp = send_simple_http_request(method, request);
  return resp;
}

//---------------------------------------------------------------------------------------------
std::vector<response> http_client::send_multi_peform_http_request(
    const std::shared_ptr<cpr::MultiPerform>& multi_perform) {
  auto future = std::async(
      [this, multi_perform] { return execute_http_request(multi_perform); });
  future.wait();
  std::vector<response> resp = future.get();
  return resp;
}

//---------------------------------------------------------------------------------------------
response http_client::send_simple_http_request(
    const method_e& method, const request& request) {
  m_sbi_logger.debug("Send a simple HTTP request");

  std::shared_ptr<cpr::Session> session = std::make_shared<cpr::Session>();
  response resp                         = {};
  cpr::Response cpr_resp                = {};

  prepare_session(method, request, session);

  // set HTTP method
  switch (method) {
    case method_e::POST: {
      cpr_resp = session->Post();
    } break;
    case method_e::GET: {
      cpr_resp = session->Get();
    } break;
    case method_e::PUT: {
      cpr_resp = session->Put();
    } break;
    case method_e::PATCH: {
      cpr_resp = session->Patch();
    } break;
    case method_e::DELETE: {
      cpr_resp = session->Delete();
    }
  }

  get_response_info(cpr_resp, resp);

  m_sbi_logger.trace(request.to_string() + " (%s)", method_to_string(method));

  return resp;
}

//---------------------------------------------------------------------------------------------
response http_client::send_async_http_request(
    const method_e& method, const request& request) {
  m_sbi_logger.info("Send an async HTTP request");

  std::shared_ptr<cpr::Session> session = std::make_shared<cpr::Session>();
  response resp                         = {};
  cpr::Response cpr_resp                = {};

  prepare_session(method, request, session);

  switch (method) {
    case method_e::POST: {
      cpr::AsyncResponse async_response = session->PostAsync();
      cpr_resp                          = async_response.get();
    } break;
    case method_e::GET: {
      cpr::AsyncResponse async_response = session->GetAsync();
      cpr_resp                          = async_response.get();
    } break;
    case method_e::PUT: {
      cpr::AsyncResponse async_response = session->PutAsync();
      cpr_resp                          = async_response.get();
    } break;
    case method_e::PATCH: {
      cpr::AsyncResponse async_response = session->PatchAsync();
      cpr_resp                          = async_response.get();
    } break;
    case method_e::DELETE: {
      cpr::AsyncResponse async_response = session->DeleteAsync();
      cpr_resp                          = async_response.get();
    }
  }

  get_response_info(cpr_resp, resp);
  m_sbi_logger.trace(request.to_string() + " (%s)", method_to_string(method));

  return resp;
}

//---------------------------------------------------------------------------------------------
std::shared_ptr<cpr::Session> http_client::add_session_to_multi_peform(
    const method_e& method, const request& request,
    const std::shared_ptr<cpr::MultiPerform>& multi_perform) {
  std::shared_ptr<cpr::Session> session = std::make_shared<cpr::Session>();

  prepare_session(method, request, session);

  // set HTTP method
  switch (method) {
    case method_e::POST: {
      session->SetBody(cpr::Body{request.body});
      multi_perform->AddSession(
          session, cpr::MultiPerform::HttpMethod::POST_REQUEST);
    } break;
    case method_e::GET: {
      multi_perform->AddSession(
          session, cpr::MultiPerform::HttpMethod::GET_REQUEST);
    } break;
    case method_e::PUT: {
      session->SetBody(cpr::Body{request.body});
      multi_perform->AddSession(
          session, cpr::MultiPerform::HttpMethod::PUT_REQUEST);
    } break;
    case method_e::PATCH: {
      session->SetBody(cpr::Body{request.body});

      multi_perform->AddSession(
          session, cpr::MultiPerform::HttpMethod::PATCH_REQUEST);
    } break;
    case method_e::DELETE: {
      multi_perform->AddSession(
          session, cpr::MultiPerform::HttpMethod::DELETE_REQUEST);
    }
  }
  return session;
}

//---------------------------------------------------------------------------------------------
void http_client::remove_session_from_multi_peform(
    const std::shared_ptr<cpr::Session>& session,
    const std::shared_ptr<cpr::MultiPerform>& multi_perform) {
  multi_perform->RemoveSession(session);
}

//---------------------------------------------------------------------------------------------
std::vector<response> http_client::execute_http_request(
    const std::shared_ptr<cpr::MultiPerform>& multi_perform) {
  std::vector<cpr::Response> responses = multi_perform->Perform();
  std::vector<response> http_responses;
  for (const auto& r : responses) {
    response resp;
    get_response_info(r, resp);
    http_responses.push_back(resp);
  }
  return http_responses;
}

//---------------------------------------------------------------------------------------------
void http_client::prepare_session(
    const method_e& method, const request& request,
    std::shared_ptr<cpr::Session>& session) {
  // Set HTTP version
  switch (m_http_version) {
    case 1:
      session->SetHttpVersion(
          cpr::HttpVersion(cpr::HttpVersionCode::VERSION_1_1));
      break;
    case 2:
      session->SetHttpVersion(
          cpr::HttpVersion(cpr::HttpVersionCode::VERSION_2_0_PRIOR_KNOWLEDGE));
      break;
  }

  // Set Interface
  session->SetInterface(cpr::Interface{m_interface});

  // Set URL
  cpr::Url url = cpr::Url{request.uri};
  session->SetUrl(url);

  // Set HTTP client timeout
  session->SetTimeout(cpr::Timeout(m_timeout_ms));

  // Set HTTP header
  cpr::Header cpr_header{};
  for (const auto& h : request.headers) {
    cpr_header.insert({h.first, h.second});
  }
  cpr_header.insert(
      {{"Expect", ""}, {"Accept", "application/json"}, {"Charset", "UTF-8"}});
  session->SetHeader(cpr_header);

  // Set HTTP method
  switch (method) {
    case method_e::POST: {
      session->SetBody(cpr::Body{request.body});
    } break;
    case method_e::GET: {
    } break;
    case method_e::PUT: {
      session->SetBody(cpr::Body{request.body});
    } break;
    case method_e::PATCH: {
      session->SetBody(cpr::Body{request.body});
    } break;
    case method_e::DELETE: {
    }
  }

  // Enable SSL/TLS
  if (m_enable_tls) {
    cpr::SslOptions sslOpts =
        cpr::Ssl(cpr::ssl::ALPN{false}, cpr::ssl::NPN{false});
    sslOpts.SetOption(cpr::ssl::TLSv1_0{});
    sslOpts.SetOption(cpr::ssl::VerifyHost{false});
    sslOpts.SetOption(cpr::ssl::VerifyPeer{false});
    sslOpts.SetOption(cpr::ssl::VerifyStatus{false});

    // TODO: Use public key
    // session->SetSslOptions(sslOpts);

    session->SetVerbose(cpr::Verbose{true});
    session->SetVerifySsl(false);  // TODO: Don't verify SSL for the moment, but
                                   // should enable this in the future
  }
}

//---------------------------------------------------------------------------------------------
void http_client::get_response_info(
    const cpr::Response& cpr_resp, response& resp) {
  resp.status_code = cpr_resp.status_code;
  resp.body        = cpr_resp.text;

  for (const auto& h : cpr_resp.header) {
    try {
      resp.headers.insert({h.first, h.second});
    } catch (std::exception&) {
      m_sbi_logger.debug(
          "Unknown header from HTTP client: '%s : %s'", h.first, h.second);
    }
  }
}

//---------------------------------------------------------------------------------------------
request http_client::prepare_json_request(
    const std::string& uri, const std::string& body) {
  request req;
  req.uri = uri;
  // Check whether body is valid JSON
  if (json::json::accept(body)) {
    req.body = body;
    req.headers.insert({"content-type", "application/json"});
  }
  return req;
}

//---------------------------------------------------------------------------------------------
request http_client::prepare_multipart_request(
    const std::string& uri, const std::string& body) {
  request req;
  req.uri  = uri;
  req.body = body;
  req.headers.insert(
      {"content-type",
       "multipart/related;boundary=" + std::string(MIME_BOUNDARY)});
  return req;
}

//---------------------------------------------------------------------------------------------
/*void http_client::enable_tls(std::string public_key_path){

}*/
