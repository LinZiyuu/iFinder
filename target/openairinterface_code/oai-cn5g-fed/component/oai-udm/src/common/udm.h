/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDM_H_SEEN
#define FILE_UDM_H_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <boost/algorithm/string.hpp>

#include "sbi_helper.hpp"

#define HEART_BEAT_TIMER 10
#define NRF_REGISTRATION_RETRY_TIMER 5

#define _unused(x) ((void) (x))

// Event Subscription IDs)
typedef uint32_t evsub_id_t;
#define EVSUB_ID_FMT "0x%" PRIx32
#define EVSUB_ID_SCAN_FMT SCNx32
#define INVALID_EVSUB_ID ((evsub_id_t) 0x00000000)
#define UNASSIGNED_EVSUB_ID ((evsub_id_t) 0x00000000)

#define NUDM_SDM_SUB "/sdm-subscriptions"
#define NUDM_SMF_SELECT "smf-select-data"
#define NUDM_NSSAI "nssai"
#define NUDM_SM_DATA "sm-data"
#define NUDM_UECM_XGPP_ACCESS "amf-3gpp-access"
#define NUDM_AM_DATA "am-data"
#define NUDM_UE_AU_EVENTS "auth-events"
#define NUDM_UE_AU_GEN_AU_DATA "generate-auth-data"

typedef struct subscriber_profile_s {
  uint8_t protection_scheme;
  std::string home_network_public_key;
  std::string home_network_private_key;
  std::string home_network_public_key_id;
} subscriber_profile_t;

#endif
