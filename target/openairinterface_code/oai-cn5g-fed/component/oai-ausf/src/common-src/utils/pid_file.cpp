/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pid_file.hpp"

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logger_base.hpp"

using namespace oai::logger;

int g_fd_pid_file = -1;
__pid_t g_pid     = -1;

//------------------------------------------------------------------------------
std::string oai::utils::get_exe_absolute_path(
    const std::string& basepath, const unsigned int instance) {
#define MAX_FILE_PATH_LENGTH 255
  char pid_file_name[MAX_FILE_PATH_LENGTH + 1] = {0};
  char* exe_basename                           = NULL;
  int rv                                       = 0;
  int num_chars                                = 0;

  // get executable name
  rv = readlink("/proc/self/exe", pid_file_name, 256);
  if (-1 == rv) {
    return NULL;
  }
  pid_file_name[rv] = 0;
  exe_basename      = basename(pid_file_name);

  // Add 6 for the other 5 characters in the path + null terminator + 2 chars
  // for instance.
  num_chars = basepath.size() + strlen(exe_basename) + 6 + 2;
  if (num_chars > MAX_FILE_PATH_LENGTH) {
    num_chars = MAX_FILE_PATH_LENGTH;
  }
  snprintf(
      pid_file_name, num_chars, "%s/%s%02u.pid", basepath.c_str(), exe_basename,
      instance);
  return std::string(pid_file_name);
}

//------------------------------------------------------------------------------
int oai::utils::lockfile(int fd, int lock_type) {
  // lock on fd only, not on file on disk (do not prevent another process from
  // modifying the file)
  return lockf(fd, F_TLOCK, 0);
}

//------------------------------------------------------------------------------
bool oai::utils::is_pid_file_lock_success(const char* pid_file_name) {
  char pid_dec[64] = {0};

  g_fd_pid_file = open(
      pid_file_name, O_RDWR | O_CREAT,
      S_IRUSR | S_IWUSR | S_IRGRP |
          S_IROTH); /* Read/write by owner, read by grp, others */
  if (0 > g_fd_pid_file) {
    logger_common::common().error(
        "open filename %s failed %d:%s\n", pid_file_name, errno,
        strerror(errno));
    return false;
  }

  if (0 > oai::utils::lockfile(g_fd_pid_file, F_TLOCK)) {
    logger_common::common().error(
        "lockfile filename %s failed %d:%s\n", pid_file_name, errno,
        strerror(errno));
    if (EACCES == errno || EAGAIN == errno) {
      close(g_fd_pid_file);
    }
    return false;
  }
  // fruncate file content
  if (ftruncate(g_fd_pid_file, 0)) {
    logger_common::common().error(
        "truncate %s failed %d:%s\n", pid_file_name, errno, strerror(errno));
    close(g_fd_pid_file);
    return false;
  }
  // write PID in file
  g_pid = getpid();
  snprintf(pid_dec, 64 /* should be big enough */, "%ld", (long) g_pid);
  if ((ssize_t) -1 == write(g_fd_pid_file, pid_dec, strlen(pid_dec))) {
    logger_common::common().error(
        "write PID to filename %s failed %d:%s\n", pid_file_name, errno,
        strerror(errno));
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void oai::utils::pid_file_unlock(void) {
  oai::utils::lockfile(g_fd_pid_file, F_ULOCK);
  close(g_fd_pid_file);
  g_fd_pid_file = -1;
}
