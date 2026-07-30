/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_DYNAMIC_MEMORY_CHECK_SEEN
#define FILE_DYNAMIC_MEMORY_CHECK_SEEN

void free_wrapper(void** ptr) __attribute__((hot));

#endif /* FILE_DYNAMIC_MEMORY_CHECK_SEEN */
