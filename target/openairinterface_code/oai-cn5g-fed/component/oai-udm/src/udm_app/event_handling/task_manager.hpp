/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TASK_MANAGER_H_
#define TASK_MANAGER_H_

#include <linux/types.h>
#include <sys/timerfd.h>

#include "udm_event.hpp"

namespace oai::udm::app {

class udm_event;
class task_manager {
 public:
  task_manager(udm_event& ev);
  ~task_manager();

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

  udm_event& event_sub_;
  int sfd;
  bool terminate;
  bool terminated;
};
}  // namespace oai::udm::app

#endif
