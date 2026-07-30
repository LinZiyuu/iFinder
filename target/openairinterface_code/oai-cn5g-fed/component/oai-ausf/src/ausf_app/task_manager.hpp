/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TASK_MANAGER_H_
#define TASK_MANAGER_H_

#include <linux/types.h>
#include <sys/timerfd.h>

#include "ausf_event.hpp"

using namespace oai::ausf::app;

namespace oai {
namespace ausf {
namespace app {

class ausf_event;
class task_manager {
 public:
  task_manager(ausf_event& ev);
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

  ausf_event& event_sub_;
  int sfd;
  bool terminate;
  bool terminated;
};
}  // namespace app
}  // namespace ausf
}  // namespace oai

#endif
