/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nef_client.hpp"

#include <curl/curl.h>
#include <pistache/http.h>

#include <nlohmann/json.hpp>
#include <stdexcept>

#include "3gpp_29.500.h"
#include "logger.hpp"
#include "nef.h"
#include "nef_config.hpp"

using namespace oai::nef::app;

extern nef_client* nef_client_inst;
extern nef_config nef_cfg;

//------------------------------------------------------------------------------
// To read content of the response from NF
static std::size_t callback(
    const char* in, std::size_t size, std::size_t num, std::string* out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

//------------------------------------------------------------------------------
nef_client::nef_client() {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_multi = curl_multi_init();
  handles    = {};
  headers    = NULL;
  headers    = curl_slist_append(headers, "Accept: application/json");
  headers    = curl_slist_append(headers, "Content-Type: application/json");
  headers    = curl_slist_append(headers, "charsets: utf-8");
  // subscribe_task_curl();
}

//------------------------------------------------------------------------------
nef_client::~nef_client() {
  Logger::nef_app().debug("Delete NEF Client instance...");
  // Remove handle, free memory
  for (auto h : handles) {
    curl_multi_remove_handle(curl_multi, h);
    curl_easy_cleanup(h);
  }

  handles.clear();
  curl_multi_cleanup(curl_multi);
  curl_global_cleanup();
  curl_slist_free_all(headers);

  // if (task_connection.connected()) task_connection.disconnect();
}

//------------------------------------------------------------------------------
void nef_client::perform_curl_multi(uint64_t ms) {
  //_unused(ms);
  int still_running = 0;
  int numfds        = 0;

  CURLMcode code = curl_multi_perform(curl_multi, &still_running);

  do {
    code = curl_multi_wait(curl_multi, NULL, 0, 200000, &numfds);
    if (code != CURLM_OK) {
      Logger::nef_app().debug("curl_multi_wait() returned %d!", code);
    }
    curl_multi_perform(curl_multi, &still_running);
  } while (still_running);

  curl_release_handles();
}

//------------------------------------------------------------------------------
void nef_client::curl_release_handles() {
  CURLMsg* curl_msg = nullptr;
  CURL* curl        = nullptr;
  CURLcode code     = {};
  int http_code     = 0;
  int msgs_left     = 0;

  while ((curl_msg = curl_multi_info_read(curl_multi, &msgs_left))) {
    if (curl_msg && curl_msg->msg == CURLMSG_DONE) {
      curl = curl_msg->easy_handle;
      code = curl_msg->data.result;

      if (code != CURLE_OK) {
        Logger::nef_app().debug("CURL error code  %d!", curl_msg->data.result);
        continue;
      }
      // Get HTTP code
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
      Logger::nef_app().debug("Got response with HTTP code  %d!", http_code);
      uint32_t* promise_id = nullptr;
      curl_easy_getinfo(curl, CURLINFO_PRIVATE, &promise_id);
      if (promise_id) {
        Logger::nef_app().debug(
            "Prepare to make promise id %d ready!", *promise_id);
        trigger_process_response(*promise_id, http_code);
      }

      curl_multi_remove_handle(curl_multi, curl);
      curl_easy_cleanup(curl);

      std::vector<CURL*>::iterator it;
      it = find(handles.begin(), handles.end(), curl);
      if (it != handles.end()) {
        handles.erase(it);
      }

    } else if (curl_msg) {
      curl = curl_msg->easy_handle;
      Logger::nef_app().debug("Error after curl_multi_info_read()");
      curl_multi_remove_handle(curl_multi, curl);
      curl_easy_cleanup(curl);

      std::vector<CURL*>::iterator it;
      it = find(handles.begin(), handles.end(), curl);
      if (it != handles.end()) {
        handles.erase(it);
      }
    } else {
      Logger::nef_app().debug("curl_msg null");
    }
  }
}

//---------------------------------------------------------------------------------------------
uint32_t nef_client::get_available_response(boost::shared_future<uint32_t>& f) {
  boost::future_status status;
  status = f.wait_for(boost::chrono::milliseconds(
      FUTURE_STATUS_TIMEOUT_MS));  // Wait for it to finish
  if (status == boost::future_status::ready) {
    assert(f.is_ready());
    assert(f.has_value());
    assert(!f.has_exception());

    uint32_t response_code = f.get();
    return response_code;
  }
  return 0;
}

//---------------------------------------------------------------------------------------------
void nef_client::add_promise(
    uint32_t id, boost::shared_ptr<boost::promise<uint32_t>>& p) {
  std::unique_lock lock(m_curl_handle_promises);
  curl_handle_promises.emplace(id, p);
}

//---------------------------------------------------------------------------------------------
void nef_client::remove_promise(uint32_t id) {
  std::unique_lock lock(m_curl_handle_promises);
  curl_handle_promises.erase(id);
}

//------------------------------------------------------------------------------
void nef_client::trigger_process_response(uint32_t pid, uint32_t http_code) {
  Logger::nef_app().debug(
      "Trigger process response: Set promise with ID %u "
      "to ready",
      pid);
  std::unique_lock lock(m_curl_handle_promises);
  if (curl_handle_promises.count(pid) > 0) {
    curl_handle_promises[pid]->set_value(http_code);
    // Remove this promise from list
    curl_handle_promises.erase(pid);
  }
}

//------------------------------------------------------------------------------
bool nef_client::curl_create_handle(
    const std::string& uri, const std::string& data, std::string& response_data,
    std::string& header_data, uint32_t* promise_id, const std::string& method,
    uint8_t http_version) {
  // Create handle for a curl request
  CURL* curl = curl_easy_init();

  if ((curl == nullptr) or (headers == nullptr)) {
    Logger::nef_app().error("Cannot initialize a new Curl Handle");
    return false;
  }

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, promise_id);

  if (method.compare("POST") == 0)
    curl_easy_setopt(curl, CURLOPT_POST, 1);
  else if (method.compare("PATCH") == 0)
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
  else if (method.compare("PUT") == 0)
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  else
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);

  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NF_CURL_TIMEOUT_MS);
  curl_easy_setopt(curl, CURLOPT_INTERFACE, nef_cfg.sbi.if_name.c_str());

  if (http_version == 2) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    // We use a self-signed test server, skip verification during debugging
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(
        curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  }

  // Hook up data handling function.
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &callback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_data);

  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  if (method.compare("DELETE") != 0) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
  }
  // Add to the multi handle
  curl_multi_add_handle(curl_multi, curl);
  handles.push_back(curl);

  // Curl cmd will actually be performed in perform_curl_multi
  perform_curl_multi(
      0);  // TODO: current time as parameter if curl is performed per event
  return true;
}

//------------------------------------------------------------------------------
void nef_client::send_event_exposure_subscribe(
    const nlohmann::json& json_body, const std::string& nf_uri,
    std::string& response_data, std::string& location, int& http_code) {
  // Generate a promise and associate this promise to the curl handle
  uint32_t promise_id = generate_promise_id();
  Logger::nef_app().debug("Promise ID generated %d", promise_id);
  uint32_t* pid_ptr = &promise_id;
  boost::shared_ptr<boost::promise<uint32_t>> p =
      boost::make_shared<boost::promise<uint32_t>>();
  boost::shared_future<uint32_t> f;
  f = p->get_future();
  add_promise(promise_id, p);

  Logger::nef_app().debug("NF URI %s", nf_uri.c_str());
  Logger::nef_app().debug("Body %s", json_body.dump().c_str());

  std::string header_data = {};
  // Create a new curl easy handle and add to the multi handle
  if (!curl_create_handle(
          nf_uri, json_body.dump(), response_data, header_data, pid_ptr,
          "POST")) {
    Logger::nef_app().warn("Could not create a new handle to send message");
    remove_promise(promise_id);
    return;
  }

  // Wait for the response back
  uint32_t response_code = get_available_response(f);
  http_code              = response_code;
  location               = get_header_location(header_data);

  Logger::nef_app().debug("Got result for promise ID %d", promise_id);
  Logger::nef_app().debug("Response code %u", response_code);
  Logger::nef_app().debug("Location %s", location.c_str());
  Logger::nef_app().debug("Response data %s", response_data.c_str());
}

//------------------------------------------------------------------------------
void nef_client::send_event_exposure_unsubscribe(
    const std::string& resource_location, std::string& response_data,
    int& http_code) {
  // Generate a promise and associate this promise to the curl handle
  uint32_t promise_id = generate_promise_id();
  Logger::nef_app().debug("Promise ID generated %d", promise_id);
  uint32_t* pid_ptr = &promise_id;
  boost::shared_ptr<boost::promise<uint32_t>> p =
      boost::make_shared<boost::promise<uint32_t>>();
  boost::shared_future<uint32_t> f;
  f = p->get_future();
  add_promise(promise_id, p);

  std::string header_data = {};
  // Create a new curl easy handle and add to the multi handle
  if (!curl_create_handle(
          resource_location, "", response_data, header_data, pid_ptr, "POST")) {
    Logger::nef_app().warn("Could not create a new handle to send message");
    remove_promise(promise_id);
    return;
  }

  // Wait for the response back
  uint32_t response_code = get_available_response(f);
  http_code              = response_code;

  Logger::nef_app().debug("Got result for promise ID %d", promise_id);
  Logger::nef_app().debug("Response code %u", response_code);
  Logger::nef_app().debug("Response data %s", response_data.c_str());
}

//------------------------------------------------------------------------------
void nef_client::send_event_exposure_notify(
    const nlohmann::json& json_body, const std::string& uri) {
  // Generate a promise and associate this promise to the curl handle
  uint32_t promise_id = generate_promise_id();
  Logger::nef_app().debug("Promise ID generated %d", promise_id);
  uint32_t* pid_ptr = &promise_id;
  boost::shared_ptr<boost::promise<uint32_t>> p =
      boost::make_shared<boost::promise<uint32_t>>();
  boost::shared_future<uint32_t> f;
  f = p->get_future();
  add_promise(promise_id, p);

  std::string header_data   = {};
  std::string response_data = {};
  // Create a new curl easy handle and add to the multi handle
  if (!curl_create_handle(
          uri, json_body.dump(), response_data, header_data, pid_ptr, "POST")) {
    Logger::nef_app().warn("Could not create a new handle to send message");
    remove_promise(promise_id);
    return;
  }

  // Wait for the response back
  uint32_t response_code = get_available_response(f);

  Logger::nef_app().debug("Got result for promise ID %d", promise_id);
  Logger::nef_app().debug("Response code %u", response_code);
  Logger::nef_app().debug("Response data %s", response_data.c_str());
}

//------------------------------------------------------------------------------
std::string nef_client::get_header_location(const std::string& header_data) {
  std::string location = {};
  // TODO
  return location;
}
