/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_COMMON_ROOT_TYPES_SEEN
#define FILE_COMMON_ROOT_TYPES_SEEN

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

//------------------------------------------------------------------------------
// TEIDs
typedef uint32_t teid_t;
#define TEID_FMT "0x%" PRIx32
#define TEID_SCAN_FMT SCNx32
#define INVALID_TEID ((teid_t) 0x00000000)
#define UNASSIGNED_TEID ((teid_t) 0x00000000)

// SEIDs
typedef uint64_t seid_t;
#define SEID_FMT "0x%" PRIx64
#define SEID_SCAN_FMT SCNx64
#define INVALID_SEID ((seid_t) 0x00000000)
#define UNASSIGNED_SEID ((seid_t) 0x00000000)

//------------------------------------------------------------------------------
// IMSI
typedef uint64_t imsi64_t;
#define IMSI_64_FMT "%" SCNu64
#define INVALID_IMSI64 (imsi64_t) 0

#endif /* FILE_COMMON_ROOT_TYPES_SEEN */
