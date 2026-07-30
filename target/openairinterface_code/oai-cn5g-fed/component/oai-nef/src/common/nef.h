/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NEF_SEEN
#define FILE_NEF_SEEN

#include <string>
#include <vector>

#define HEART_BEAT_TIMER 10

#define _unused(x) ((void) (x))

typedef enum nf_type_s {
  NF_TYPE_NRF     = 0,
  NF_TYPE_AMF     = 1,
  NF_TYPE_SMF     = 2,
  NF_TYPE_AUSF    = 3,
  NF_TYPE_NEF     = 4,
  NF_TYPE_PCF     = 5,
  NF_TYPE_SMSF    = 6,
  NF_TYPE_NSSF    = 7,
  NF_TYPE_UDR     = 8,
  NF_TYPE_LMF     = 9,
  NF_TYPE_GMLC    = 10,
  NF_TYPE_5G_EIR  = 11,
  NF_TYPE_SEPP    = 12,
  NF_TYPE_UPF     = 13,
  NF_TYPE_N3IWF   = 14,
  NF_TYPE_AF      = 15,
  NF_TYPE_UDSF    = 16,
  NF_TYPE_BSF     = 17,
  NF_TYPE_CHF     = 18,
  NF_TYPE_NWDAF   = 19,
  NF_TYPE_UNKNOWN = 20
} nf_type_t;

static const std::vector<std::string> nf_type_e2str = {
    "NRF",   "AMF", "SMF",  "AUSF", "NEF",    "PCF",   "SMSF",
    "NSSF",  "UDR", "LMF",  "GMLC", "5G_EIR", "SEPP",  "UPF",
    "N3IWF", "AF",  "UDSF", "BSF",  "CHF",    "NWDAF", "UNKNOWN"};

typedef enum patch_op_type_s {
  PATCH_OP_ADD     = 0,
  PATCH_OP_REMOVE  = 1,
  PATCH_OP_REPLACE = 2,
  PATCH_OP_MOVE    = 3,
  PATCH_OP_COPY    = 4,
  PATCH_OP_TEST    = 5,
  PATCH_OP_UNKNOWN = 6

} patch_op_type_t;

static const std::vector<std::string> patch_op_type_e2str = {
    "ADD", "REMOVE", "REPLACE", "MOVE", "COPY", "TEST", "UNKNOWN"};

// Event Subscription IDs)
typedef uint32_t evsub_id_t;
#define EVSUB_ID_FMT "0x%" PRIx32
#define EVSUB_ID_SCAN_FMT SCNx32
#define INVALID_EVSUB_ID ((evsub_id_t) 0x00000000)
#define UNASSIGNED_EVSUB_ID ((evsub_id_t) 0x00000000)

#define NNEF_MONITORING_EVENT_BASE "/3gpp-monitoring-event/"
#define NNEF_EVENT_EXPOSURE_BASE "/nnef-eventexposure/"
#define NNEF_NFM_NF_INSTANCES "/nf-instances/"
#define NNEF_EE_SUBSCRIPTION_URL "/subscriptions"
#define NNEF_EE_SUBSCRIPTION_NOTIFY_URL "/subscriptions/notify"

#define NAMF_EVENT_EXPOSURE_BASE "/namf-evts/"

#define NF_CURL_TIMEOUT_MS 1000L
#define FUTURE_STATUS_TIMEOUT_MS 100

#define MAX_WAIT_MSECS 20000  // 1 second

#endif
