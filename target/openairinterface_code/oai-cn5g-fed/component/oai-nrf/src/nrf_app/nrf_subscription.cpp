/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nrf_subscription.hpp"

#include <boost/date_time/posix_time/time_formatters.hpp>
#include <nlohmann/json.hpp>

#include "logger.hpp"

using namespace oai::nrf::app;
using namespace boost::placeholders;

//------------------------------------------------------------------------------
void nrf_subscription::set_subscription_id(const std::string& sub) {
  subscription_id = sub;
}

//------------------------------------------------------------------------------
void nrf_subscription::get_subscription_id(std::string& sub) const {
  sub = subscription_id;
}

//------------------------------------------------------------------------------
std::string nrf_subscription::get_subscription_id() const {
  return subscription_id;
}

//------------------------------------------------------------------------------
void nrf_subscription::set_notification_uri(
    const std::string& notification_uri) {
  nf_status_notification_uri = notification_uri;
}

//------------------------------------------------------------------------------
void nrf_subscription::get_notification_uri(
    std::string& notification_uri) const {
  notification_uri = nf_status_notification_uri;
}

//------------------------------------------------------------------------------
void nrf_subscription::set_sub_condition(const subscription_condition_t& c) {
  sub_condition = c;
}

//------------------------------------------------------------------------------
void nrf_subscription::get_sub_condition(subscription_condition_t& c) const {
  c = sub_condition;
}

//------------------------------------------------------------------------------
/*
subscription_condition_t nrf_subscription::get_sub_condition() const {
  return sub_condition;
}
*/

//------------------------------------------------------------------------------
void nrf_subscription::set_notif_events(const std::vector<uint8_t>& ev_types) {
  notif_events = ev_types;
}

//------------------------------------------------------------------------------
void nrf_subscription::add_notif_event(const uint8_t& ev_type) {
  notif_events.push_back(ev_type);
}

//------------------------------------------------------------------------------
void nrf_subscription::get_notif_events(std::vector<uint8_t>& ev_types) const {
  ev_types = notif_events;
}

//------------------------------------------------------------------------------
std::vector<uint8_t> nrf_subscription::get_notif_events() const {
  return notif_events;
}

//------------------------------------------------------------------------------
void nrf_subscription::set_validity_time(const boost::posix_time::ptime& t) {
  validity_time = t;
}

//------------------------------------------------------------------------------
void nrf_subscription::get_validity_time(boost::posix_time::ptime& t) const {
  t = validity_time;
}

//------------------------------------------------------------------------------
boost::posix_time::ptime nrf_subscription::get_validity_time() const {
  return validity_time;
}

//------------------------------------------------------------------------------
void nrf_subscription::set_http_version(const uint8_t& httpVersion) {
  http_version = httpVersion;
}

//------------------------------------------------------------------------------
uint8_t nrf_subscription::get_http_version() const {
  return http_version;
}

//------------------------------------------------------------------------------
void nrf_subscription::display() {
  Logger::nrf_app().debug("Subscription information");
  Logger::nrf_app().debug("\tSub ID: %s", subscription_id.c_str());

  Logger::nrf_app().debug(
      "\tNotification URI: %s", nf_status_notification_uri.c_str());
  Logger::nrf_app().debug(
      "\tSubscription condition: %s", sub_condition.to_string().c_str());

  std::string notif_events_str = {};
  for (auto n : notif_events) {
    notif_events_str.append(notification_event_type_e2str[n]);
    notif_events_str.append(", ");
  }
  Logger::nrf_app().debug(
      "\tNotification Events: %s", notif_events_str.c_str());
  Logger::nrf_app().debug(
      "\tValidity time: %s",
      boost::posix_time::to_iso_string(validity_time).c_str());
}

//------------------------------------------------------------------------------
void nrf_subscription::subscribe_nf_status_registered() {
  Logger::nrf_app().debug("Subscribe to NF status change event");
  ev_connection =
      m_event_sub.subscribe_nf_status_change(  // TODO: To be updated
          boost::bind(
              &nrf_subscription::handle_nf_status_registered, this, _1));
}

//------------------------------------------------------------------------------
void nrf_subscription::handle_nf_status_registered(
    const std::shared_ptr<nrf_profile>& profile) {
  std::string nf_instance_id;
  profile.get()->get_nf_instance_id(nf_instance_id);
  Logger::nrf_app().info(
      "Handle NF status registered (subscription ID %s), profile ID %s",
      subscription_id.c_str(), nf_instance_id.c_str());
  // TODO:
  nlohmann::json notification_data   = {};
  notification_data["event"]         = "NF_REGISTERED";
  notification_data["nfInstanceUri"] = "";
  // get NF profile based on profile_id
  // NFStatusNotify
  // curl...
}
