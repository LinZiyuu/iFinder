/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDR_SEEN
#define FILE_UDR_SEEN

#include <string>

#define HEART_BEAT_TIMER 10
#define NRF_REGISTRATION_RETRY_TIMER 5

#define MAX_FIRST_CONNECTION_RETRY 100
#define MAX_CONNECTION_RETRY 3

#define _unused(x) ((void) (x))

#define NUDR_DR_AUTH_STATUS "authentication-status"
#define NUDR_DR_AUTH_SUBS "authentication-subscription"
#define NUDR_DR_AMF_XGPP_ACCESS "amf-3gpp-access"
#define NUDR_DR_AM_DATA "am-data"
#define NUDR_DR_SDM_SUBS "sdm-subscriptions"
#define NUDR_DR_SM_DATA "sm-data"
#define NUDR_DR_SMF_REG "smf-registrations"
#define NUDR_DR_SMF_SELECT "smf-selection-subscription-data"

// Database collection/table names and labels
constexpr auto DATABASE_AUTHENTICATION_SUBSCRIPTION =
    "AuthenticationSubscription";
constexpr auto DATABASE_AUTHENTICATION_SUBSCRIPTION_LABEL =
    "Authentication Subscription";
constexpr auto DATABASE_AMF_3GPP_ACCESS_REGISTRATION =
    "Amf3GppAccessRegistration";
constexpr auto DATABASE_AMF_3GPP_ACCESS_REGISTRATION_LABEL =
    "AMF 3GPP Access Registration";
constexpr auto DATABASE_ACCESS_AND_MOBILITY_SUBSCRIPTION_DATA =
    "AccessAndMobilitySubscriptionData";
constexpr auto DATABASE_ACCESS_AND_MOBILITY_SUBSCRIPTION_DATA_LABEL =
    "Access and Mobility Subscription Data";
constexpr auto DATABASE_SDM_SUBSCRIPTIONS       = "SdmSubscriptions";
constexpr auto DATABASE_SDM_SUBSCRIPTIONS_LABEL = "SDM Subscriptions";
constexpr auto DATABASE_SESSION_MANAGEMENT_SUBSCRIPTION_DATA =
    "SessionManagementSubscriptionData";
constexpr auto DATABASE_SESSION_MANAGEMENT_SUBSCRIPTION_DATA_LABEL =
    "Session Management Subscription Data";
constexpr auto DATABASE_SMF_REGISTRATIONS           = "SmfRegistrations";
constexpr auto DATABASE_SMF_REGISTRATIONS_LABEL     = "SMF Registrations";
constexpr auto DATABASE_AUTHENTICATION_STATUS       = "AuthenticationStatus";
constexpr auto DATABASE_AUTHENTICATION_STATUS_LABEL = "Authentication Status";
constexpr auto DATABASE_SMF_SELECTION_SUBSCRIPTION_DATA =
    "SmfSelectionSubscriptionData";
constexpr auto DATABASE_SMF_SELECTION_SUBSCRIPTION_DATA_LABEL =
    "SMF Selection Subscription Data";

typedef enum db_type_s {
  DB_TYPE_UNKNOWN   = 0,
  DB_TYPE_MYSQL     = 1,
  DB_TYPE_CASSANDRA = 2,
  DB_TYPE_MONGODB   = 3
} db_type_t;

static std::string db_type_to_string(db_type_t db_type) {
  switch (db_type) {
    case db_type_t::DB_TYPE_UNKNOWN:
      return "Unknown";
    case db_type_t::DB_TYPE_MYSQL:
      return "MySQL";
    case db_type_t::DB_TYPE_CASSANDRA:
      return "Cassandra";
    case db_type_t::DB_TYPE_MONGODB:
      return "MongoDb";
    default:
      return "Unknown";
  }
  return "Unknown";
}

#endif
