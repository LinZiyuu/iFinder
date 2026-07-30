/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NEF_CLIENT_HPP_SEEN
#define FILE_NEF_CLIENT_HPP_SEEN

#include <curl/curl.h>

#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "uint_generator.hpp"

namespace oai::nef::app {

class nef_client {
 private:
  CURLM* curl_multi;
  std::vector<CURL*> handles;
  struct curl_slist* headers;

  mutable std::shared_mutex m_curl_handle_promises;
  std::map<uint32_t, boost::shared_ptr<boost::promise<uint32_t>>>
      curl_handle_promises;

 public:
  //  nef_client(nef_event& ev);
  nef_client();
  virtual ~nef_client();

  nef_client(nef_client const&) = delete;
  void operator=(nef_client const&) = delete;

  /*
   * Create Curl handle for multi curl
   * @param [const std::string &] uri: URI of the subscribed NF
   * @param [std::string &] response_data: response data
   * @param [uint32_t* ] promise_id: pointer to the promise id
   * @param [const std::string&] method: HTTP method
   * @return true if a handle was created successfully, otherwise return false
   */
  bool curl_create_handle(
      const std::string& uri, const std::string& data,
      std::string& response_data, std::string& header_data,
      uint32_t* promise_id, const std::string& method,
      uint8_t http_version = 1);

  /*
   * Perform curl multi to actually process the available data
   * @param [uint64_t ms] ms: current time
   * @return void
   */
  void perform_curl_multi(uint64_t ms);

  /*
   * Release all the handles
   * @param void
   * @return void
   */
  void curl_release_handles();

  /*
   * Wait for the promise ready
   * @param [boost::shared_future<uint32_t>&] f: future
   * @return future value
   */
  uint32_t get_available_response(boost::shared_future<uint32_t>& f);

  /*
   * Store the promise
   * @param [uint32_t] pid: promise id
   * @param [boost::shared_ptr<boost::promise<uint32_t>>&] p: promise
   * @return void
   */
  void add_promise(
      uint32_t pid, boost::shared_ptr<boost::promise<uint32_t>>& p);

  /*
   * Remove the promise
   * @param [uint32_t] pid: promise id
   * @return void
   */
  void remove_promise(uint32_t id);

  /*
   * Set the value of the promise to make it ready
   * @param [uint32_t] pid: promise id
   * @param [uint32_t ] http_code: http response code
   * @return void
   */
  void trigger_process_response(uint32_t pid, uint32_t http_code);

  /*
   * Generate an unique value for promise id
   * @param void
   * @return generated promise id
   */
  static uint64_t generate_promise_id() {
    return util::uint_uid_generator<uint64_t>::get_instance().get_uid();
  }

  /*
   * Get header location from the response from NFs
   * @param [const std::string&] header_data: HTTP header
   * @return header location
   */
  std::string get_header_location(const std::string& header_data);

  /*
   * Send a request to subscribe to Event Exposure service from a NF
   * @param [const nlohmann::json&] json_body: Request body
   * @param [const std::string &] nf_uri: URI of the subscribed NF
   * @param [std::string &] response_data: response data
   * @param [std::string&] location: Store the location of created resource for
   * this Sub
   * @param [int&] http_code: HTTP response code
   * @return void
   */
  void send_event_exposure_subscribe(
      const nlohmann::json& json_body, const std::string& uri,
      std::string& response_data, std::string& location, int& http_code);

  /*
   * Send a request to unsubscribe to Event Exposure service from a NF
   * @param [const std::string &] resource_location: URI of the resource
   * location (subscription)
   * @param [std::string &] response_data: response data
   * @param [int&] http_code: HTTP response code
   * @return void
   */
  void send_event_exposure_unsubscribe(
      const std::string& resource_location, std::string& response_data,
      int& http_code);

  /*
   * Send an Event Exposure Notification data to the subscribed NF
   * @param [const nlohmann::json&] json_body: message body
   * @param [const std::string &] nf_uri: URI of the subscribed NF
   * @return void
   */
  void send_event_exposure_notify(
      const nlohmann::json& json_body, const std::string& uri);
};
}  // namespace oai::nef::app
#endif /* FILE_NEF_CLIENT_HPP_SEEN */
