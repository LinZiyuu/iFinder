/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDR_NRF_SEEN
#define FILE_UDR_NRF_SEEN

#include <curl/curl.h>

#include <map>
#include <thread>

#include "logger.hpp"
#include "udr_config.hpp"
#include "udr_event.hpp"
#include "udr_profile.hpp"

namespace oai {
namespace udr {
namespace app {

class udr_nrf {
 private:
 public:
  // timer_id_t timer_udr_heartbeat;

  udr_nrf(udr_event& ev);
  udr_nrf(udr_nrf const&) = delete;
  void operator=(udr_nrf const&) = delete;

  void start();
  void stop();

  /*
   * Start event nf heartbeat procedure
   * @param [void]
   * @return void
   */
  void start_event_nf_heartbeat(std::string& remoteURI);
  /*
   * Trigger NF heartbeat procedure
   * @param [void]
   * @return void
   */
  void trigger_nf_heartbeat_procedure(uint64_t ms);

  /*
   * Start event nrf registration retry
   * @param [void]
   * @return void
   */
  void start_nrf_registration_retry();

  /*
   * Trigger NF registration procedure
   * @param [void]
   * @return void
   */
  void trigger_nrf_registration_retry_procedure(uint64_t ms);

  /*
   * Stop event nrf registration retry
   * @param [void]
   * @return void
   */
  void stop_nrf_registration_retry();

  /*
   * Generate a UDR profile for this instance
   * @param [void]
   * @return void
   */
  void generate_udr_profile();

  /*
   * Trigger NF instance registration to NRF
   * @param [void]
   * @return void
   */
  void register_to_nrf();

  /*
   * Trigger NF instance deregistration to NRF
   * @param [void]
   * @return void
   */
  void deregister_to_nrf();

 private:
  udr_event& m_event_sub;
  bs2::connection task_connection;
  bs2::connection retry_nrf_registration_task_connection;
  udr_profile udr_nf_profile;   // UDR profile
  std::string udr_instance_id;  // UDR instance id
};
}  // namespace app
}  // namespace udr
}  // namespace oai
#endif /* FILE_UDR_NRF_SEEN */
