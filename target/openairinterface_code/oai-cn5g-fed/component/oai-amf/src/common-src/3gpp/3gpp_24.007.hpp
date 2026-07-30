/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_24_007_SEEN
#define FILE_3GPP_24_007_SEEN

#include <stdint.h>

constexpr uint8_t kType1IeSize = 1;

// Extended Protocol Discriminator (EPD)
constexpr uint8_t k5gsSessionManagementMessages  = 0b00101110;
constexpr uint8_t k5gsMobilityManagementMessages = 0b01111110;

typedef enum extended_protocol_discriminator_e {
  // 5G Session Management
  EPD_5GS_SESSION_MANAGEMENT_MESSAGES = 0x2e,
  // 5G Mobility Management
  EPD_5GS_MOBILITY_MANAGEMENT_MESSAGES = 0x7e,

} extended_protocol_discriminator_t;

// Procedure transaction identity
// 8 bits
#define PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED (uint8_t) 0
#define PROCEDURE_TRANSACTION_IDENTITY_FIRST (uint8_t) 1
#define PROCEDURE_TRANSACTION_IDENTITY_LAST (uint8_t) 254
#define PROCEDURE_TRANSACTION_IDENTITY_RESERVED (uint8_t) 255

// PDU Session Identity
typedef uint8_t pdu_session_id_t;

// 8 bits
#define PDU_SESSION_IDENTITY_UNASSIGNED (uint8_t) 0
#define PDU_SESSION_IDENTITY_FIRST (uint8_t) 1
#define PDU_SESSION_IDENTITY_LAST (uint8_t) 15

// QFI
// type: integer,  minimum: 0, maximum: 63
#define NO_QOS_FLOW_IDENTIFIER_ASSIGNED (uint8_t) 0
#define QOS_FLOW_IDENTIFIER_FIRST (uint8_t) 1
#define QOS_FLOW_IDENTIFIER_LAST (uint8_t) 63

// QoS Rule
#define NO_QOS_RULE_IDENTIFIER_ASSIGNED (uint8_t) 0
#define QOS_RULE_IDENTIFIER_FIRST (uint8_t) 1
#define QOS_RULE_IDENTIFIER_LAST (uint8_t) 255

#endif
