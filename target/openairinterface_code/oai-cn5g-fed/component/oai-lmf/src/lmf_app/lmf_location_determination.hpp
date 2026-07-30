/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_LOCATION_DETERMINATION_SEEN
#define FILE_LMF_LOCATION_DETERMINATION_SEEN

#include <future>
#include <map>
#include <tuple>
#include <set>
#include <variant>
#include <shared_mutex>
#include <cmath>

#include <nlohmann/json.hpp>

#include <pistache/http.h>
#include <pistache/router.h>

#include "lmf_gnb.hpp"
#include "lmf_cause_error.hpp"

#include "NRPPA-PDU.h"
#include "NRPPATransactionID.h"
#include "PositioningInformationResponse.h"
#include "MeasurementResponse.h"
#include "PositioningActivationResponse.h"
#include "SRSConfiguration.h"
#include "ProcedureCode.h"
#include "Measurement-ID.h"
#include "TRPInformationResponse.h"
#include "LocationData.h"

#include "GlobalRanNodeId.h"
#include "TRP-ID.h"
#include "PositioningInformationFailure.h"
#include "PositioningActivationFailure.h"
#include "ULRTOAMeas.h"
#include "TRP-MeasurementResponseList.h"
#include "MeasurementFailure.h"
#include "position_estimation.hpp"
namespace oai::lmf::app {

using NrppaPduShared = std::shared_ptr<NRPPA_PDU_t>;
NrppaPduShared share_nrppa_pdu(NRPPA_PDU_t* ptr);

class LocationDetermination {
 public:
  LocationDetermination(std::string supi);
  virtual ~LocationDetermination();

  using pos_act_succ = NrppaPduShared;
  using pos_act_res  = std::variant<pos_act_succ, CauseError>;
  std::promise<pos_act_res> positioning_activation_response;
  pos_act_res positioning_activation_request();
  void handle_positioning_activation_response(
      NrppaPduShared nrppaPdu, NRPPATransactionID_t const& tId,
      PositioningActivationResponse_t const& positioningActivationResponse);
  void handle_positioning_activation_failure(
      NrppaPduShared nrppa,
      PositioningActivationFailure_t const& positioningActivationFailure);
  bool positioning_deactivation_request();

  using pos_info_succ = std::tuple<NrppaPduShared, SRSConfiguration_t const&>;
  using pos_info_res  = std::variant<pos_info_succ, CauseError>;
  std::promise<pos_info_res> positioning_information_response;
  pos_info_res positioning_information_request();
  void handle_positioning_information_response(
      NrppaPduShared nrppaPdu, NRPPATransactionID_t const& tId,
      PositioningInformationResponse_t const& positioningInformationResponse);
  void handle_positioning_information_failure(
      NrppaPduShared nrppaPdu,
      PositioningInformationFailure_t const& positioningInformationFailure);

  using mmr_succ =
      std::tuple<NrppaPduShared, TRP_MeasurementResponseList_t const&>;
  using mmr_res = std::variant<mmr_succ, CauseError>;
  std::promise<mmr_res> measurement_response;
  mmr_res measurement_request(
      oai::lmf::app::Gnb const& gnb,
      SRSConfiguration_t const& srsConfiguration);
  void handle_measurement_response(
      NrppaPduShared nrppaPdu,
      MeasurementResponse_t const& measurementResponse);
  void handle_measurement_failure(
      NrppaPduShared nrppaPdu, MeasurementFailure_t const& measurementFailure);
  void collectResult(
      oai::lmf::app::Gnb const& gnb,
      TRP_MeasurementResponseList_t const& measurementResponse);

  bool n1_n2_message_transfer(
      NrppaPduShared nrppaPdu, NRPPATransactionID_t const& txnId,
      ProcedureCode_t const& procedureCode);
  bool non_ue_n2_message_transfer(
      NrppaPduShared nrppaPdu, NRPPATransactionID_t const& txnId,
      ProcedureCode_t const& procedureCode,
      std::vector<oai::model::common::GlobalRanNodeId> const& grnidl,
      SRSConfiguration_t* const srsConfigurationBorrowed = nullptr);

  // mapping between nrppa transaction and transaction type
  // TODO: use individual reponse object as value not ResposeType
  //       to have more than one measurement at same time
  std::map<NRPPATransactionID_t, ProcedureCode_t> nrppa_tId;

  void throwHttpError(
      std::string const& title, std::string const& detail,
      Pistache::Http::Code const& code =
          Pistache::Http::Code::Internal_Server_Error);

  nlohmann::json compute_location(
      std::map<oai::lmf::app::GnbId, oai::lmf::app::Gnb> const& gnb);

  std::string supi;
  Measurement_ID_t const measurementId;

  mutable std::shared_mutex m_result;
  std::map<
      oai::lmf::app::GnbId, std::map<TRP_ID_t, std::map<ULRTOAMeas_PR, long>>>
      result;

  template<typename T>
  T wait_for_notification(
      std::string const& kind, NRPPATransactionID_t const& tId,
      std::promise<T>& p, std::chrono::milliseconds const& wait_ms);
};
}  // namespace oai::lmf::app

#endif  // FILE_LMF_LOCATION_DETERMINATION_SEEN
