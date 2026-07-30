/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_AUSF_NRF_SEEN
#define FILE_AUSF_NRF_SEEN

#include "PatchItem.h"
#include "ausf_config.hpp"
#include "ausf_event.hpp"
#include "ausf_profile.hpp"
#include "logger.hpp"

namespace oai {
namespace ausf {
namespace app {

class ausf_nrf {
 public:
  ausf_profile ausf_nf_profile;  // AUSF profile
  std::string ausf_instance_id;  // AUSF instance id

  ausf_nrf(ausf_event& ev);
  ausf_nrf(ausf_nrf const&) = delete;
  virtual ~ausf_nrf();

  void operator=(ausf_nrf const&) = delete;

  void generate_uuid();

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
   * Generate a AUSF profile for this instance
   * @param [void]
   * @return void
   */
  void generate_ausf_profile();

  /*
   * Get NF instance ID
   * @param void
   * @return instance id
   */
  std::string get_nf_instance_id() const;

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
  ausf_event& m_event_sub;
  bs2::connection task_connection;
  bs2::connection retry_nrf_registration_task_connection;
};
}  // namespace app
}  // namespace ausf
}  // namespace oai
#endif /* FILE_AUSF_NRF_SEEN */
