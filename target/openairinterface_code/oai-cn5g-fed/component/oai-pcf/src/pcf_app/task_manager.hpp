/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TASK_MANAGER_H_
#define TASK_MANAGER_H_

#include "pcf_event.hpp"

#include <linux/types.h>
#include <sys/timerfd.h>

using namespace oai::pcf::app;

namespace oai {
namespace pcf {
namespace app {

class pcf_event;
class task_manager {
 public:
  task_manager(pcf_event& ev);

  /*
   * Manage the tasks
   * @param [void]
   * @return void
   */
  void manage_tasks();

  /*
   * Run the tasks (for the moment, simply call function manage_tasks)
   * @param [void]
   * @return void
   */
  void run();

 private:
  /*
   * Make sure that the task tick run every 1ms
   * @param [void]
   * @return void
   */
  void wait_for_cycle();

  pcf_event& event_sub_;
  int sfd;
};
}  // namespace app
}  // namespace pcf
}  // namespace oai

#endif
