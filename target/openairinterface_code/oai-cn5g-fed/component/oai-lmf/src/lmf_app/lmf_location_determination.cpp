/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_location_determination.hpp"

#include <boost/range/adaptor/map.hpp>
#include <optional>

#include "3gpp_29.518.h"
#include "AperiodicSRS.h"
#include "InitiatingMessage.h"
#include "LocationData.h"
#include "N1N2MessageTransferReqData.h"
#include "N2InfoContainer.h"
#include "N2InfoContent.h"
#include "N2InformationClass.h"
#include "N2InformationTransferReqData.h"
#include "NgapIeType.h"
#include "NrppaInformation.h"
#include "ProblemDetails.h"
#include "ProtocolIE-Field.h"
#include "SemipersistentSRS.h"
#include "TRP-MeasurementRequestItem.h"
#include "TRP-MeasurementResponseItem.h"
#include "TRPInformationItem.h"
#include "TrpMeasuredResultsValue.h"
#include "TrpMeasurementResultItem.h"
#include "UL-RTOAMeasurement.h"
#include "ULRTOAMeas.h"
#include "conversions.hpp"
#include "http_client.hpp"
#include "lmf.h"
#include "lmf_app.hpp"
#include "lmf_cause_error.hpp"
#include "lmf_nrf.hpp"
#include "lmf_sbi_helper.hpp"
#include "logger.hpp"
#include "mime_parser.hpp"
#include "position_estimation.hpp"

using namespace std::string_literals;
using namespace oai::model::lmf;
using namespace oai::lmf::app;
using namespace oai::lmf::api;
using namespace oai::model::common;

extern std::shared_ptr<oai::http::http_client> http_client_inst;

// provides for asn container.list.array range based for loops
// for (auto const& xyzIEs : xyzResponse.protocolIEs) {
template<typename T>
auto begin(T const& container) {
  return container.list.array;
}

//------------------------------------------------------------------------------
template<typename T>
auto end(T const& container) {
  return container.list.array + container.list.count;
}

//------------------------------------------------------------------------------
template<
    class result_t   = std::chrono::milliseconds,
    class clock_t    = std::chrono::steady_clock,
    class duration_t = std::chrono::milliseconds>
auto elapsed_ms(std::chrono::time_point<clock_t, duration_t> const& start) {
  return std::chrono::duration_cast<result_t>(clock_t::now() - start).count();
}

//------------------------------------------------------------------------------
std::shared_ptr<NRPPA_PDU_t> oai::lmf::app::share_nrppa_pdu(NRPPA_PDU_t* ptr) {
  return {
      ptr, [](NRPPA_PDU_t* ptr) { ASN_STRUCT_FREE(asn_DEF_NRPPA_PDU, ptr); }};
}

//------------------------------------------------------------------------------
LocationDetermination::LocationDetermination(std::string supi)
    : supi{supi}, measurementId{lmf_app_inst->measurement_id_gen.get_uid()} {}

//------------------------------------------------------------------------------
LocationDetermination::~LocationDetermination() {
  lmf_app_inst->measurement_id_gen.free_uid(this->measurementId);
}

//------------------------------------------------------------------------------
bool LocationDetermination::n1_n2_message_transfer(
    NrppaPduShared nrppaPdu, NRPPATransactionID_t const& txnId,
    ProcedureCode_t const& procedureCode) {
  Logger::lmf_app().info("n1_n2_message_transfer");
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppaPdu.get());

  asn_encode_to_new_buffer_result_t nrppaPduEnc = asn_encode_to_new_buffer(
      0, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_NRPPA_PDU, nrppaPdu.get());

  if (nrppaPduEnc.result.encoded == -1) {
    Logger::lmf_app().error(
        "Could not encode (at %s)\n", nrppaPduEnc.result.failed_type ?
                                          nrppaPduEnc.result.failed_type->name :
                                          "unknown");
    auto const& title  = "asn nrppa encode failed"s;
    auto const& field  = nrppaPduEnc.result.failed_type ?
                             nrppaPduEnc.result.failed_type->name :
                             "unknown";
    auto const& detail = "Could not encode at; "s + field;
    throwHttpError(title, detail);
  }
  // gc free(nrppaPduEnc.buffer)
  std::unique_ptr<void, decltype(&std::free)> gc{
      nrppaPduEnc.buffer, &std::free};

  std::string amf_uri  = {};
  std::string response = {};
  lmf_sbi_helper::get_amf_comm_n1n2_message_transfer_uri(
      lmf_cfg.amf_addr, this->supi, amf_uri);
  Logger::lmf_app().debug("AMF's URI %s", amf_uri.c_str());

  std::string nrppaMsgStr(
      (char*) nrppaPduEnc.buffer, nrppaPduEnc.result.encoded);
  std::string nrppaMsgHex = {};
  oai::utils::conv::convert_string_2_hex(nrppaMsgStr, nrppaMsgHex);

  RefToBinaryData ngapData = {};
  ngapData.setContentId(N2_NRPPa_CONTENT_ID);

  NgapIeType ngapIeType = {};
  ngapIeType.setEnumValue(NgapIeType_anyOf::eNgapIeType_anyOf::NRPPA_PDU);

  N2InfoContent n2InfoContent = {};
  n2InfoContent.setNgapIeType(ngapIeType);
  n2InfoContent.setNgapData(ngapData);

  NrppaInformation nrppaInformation = {};
  nrppaInformation.setNfId(lmf_nrf_inst->lmf_nf_profile.get_nf_instance_id());
  nrppaInformation.setNrppaPdu(n2InfoContent);

  N2InformationClass n2InformationClass = {};
  n2InformationClass.setEnumValue(
      N2InformationClass_anyOf::eN2InformationClass_anyOf::NRPPA);
  N2InfoContainer n2InfoContainer = {};
  n2InfoContainer.setN2InformationClass(n2InformationClass);
  n2InfoContainer.setNrppaInfo(nrppaInformation);

  N1N2MessageTransferReqData n1n2MessageTransferReqData = {};
  n1n2MessageTransferReqData.setN2InfoContainer(n2InfoContainer);

  nlohmann::json n1n2MessageTransferReq_json;
  to_json(n1n2MessageTransferReq_json, n1n2MessageTransferReqData);

  std::string body      = {};
  std::string json_part = {};
  json_part             = n1n2MessageTransferReq_json.dump();

  mime_parser::create_multipart_related_content(
      body, json_part, CURL_MIME_BOUNDARY, nrppaMsgHex,
      multipart_related_content_part_e::NGAP);

  if (auto const& [iter, inserted] =
          this->nrppa_tId.try_emplace(txnId, procedureCode);
      !inserted) {
    throwHttpError(
        "n1_n2_message_transfer"s,
        "nrppa id "s + std::to_string(txnId) + " reuse"s);
  }

  // Send HTTP request
  oai::http::request http_request =
      http_client_inst->prepare_multipart_request(amf_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);
  response = http_response.body;

  Logger::lmf_app().info("Response from AMF: %s", response);

  auto const& rspData_json = nlohmann::json::parse(response);
  if (!rspData_json.contains("cause") ||
      rspData_json["cause"] !=
          n1_n2_message_transfer_cause_e2str[N1_N2_TRANSFER_INITIATED]) {
    this->nrppa_tId.erase(txnId);
    lmf_app_inst->nrppa_tid_gen.free_uid(txnId);

    auto const& title = "n1n2message transfer failed"s;
    auto const& cause =
        rspData_json.contains("cause") ?
            n1_n2_message_transfer_cause_e2str[rspData_json["cause"]] :
            "no cause"s;
    auto const& detail = "supi: '"s + this->supi + "': cause: "s + cause;
    throwHttpError(title, detail);
  }

  return true;
}

//------------------------------------------------------------------------------
bool LocationDetermination::non_ue_n2_message_transfer(
    NrppaPduShared nrppaPdu, NRPPATransactionID_t const& txnId,
    ProcedureCode_t const& procedureCode,
    std::vector<GlobalRanNodeId> const& globalRanNodeList,
    SRSConfiguration_t* const ueSrsConfigurationShared) {
  Logger::lmf_app().info("non_ue_n2_message_transfer");
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppaPdu.get());

  asn_encode_to_new_buffer_result_t nrppaPduEnc = asn_encode_to_new_buffer(
      0, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_NRPPA_PDU, nrppaPdu.get());
  if (ueSrsConfigurationShared != nullptr) {
    // don't free, it's from positioning information request
    *ueSrsConfigurationShared = {};
  }

  if (nrppaPduEnc.result.encoded == -1) {
    Logger::lmf_app().error(
        "Could not encode (at %s)\n", nrppaPduEnc.result.failed_type ?
                                          nrppaPduEnc.result.failed_type->name :
                                          "unknown");
    auto const& title  = "asn nrppa encode failed"s;
    auto const& field  = nrppaPduEnc.result.failed_type ?
                             nrppaPduEnc.result.failed_type->name :
                             "unknown";
    auto const& detail = "Could not encode at; "s + field;
    throwHttpError(title, detail);
  }
  std::unique_ptr<void, decltype(&std::free)> gc{
      nrppaPduEnc.buffer, &std::free};

  std::string amf_uri  = {};
  std::string method   = "POST";
  std::string response = {};
  lmf_sbi_helper::get_amf_comm_non_ue_n1n2_message_transfer_uri(
      lmf_cfg.amf_addr, amf_uri);

  Logger::lmf_app().debug("AMF's URI %s", amf_uri.c_str());

  std::string nrppaMsgStr(
      (char*) nrppaPduEnc.buffer, nrppaPduEnc.result.encoded);
  std::string nrppaMsgHex = {};
  oai::utils::conv::convert_string_2_hex(nrppaMsgStr, nrppaMsgHex);

  RefToBinaryData ngapData = {};
  ngapData.setContentId(N2_NRPPa_CONTENT_ID);

  NgapIeType ngapIeType = {};
  ngapIeType.setEnumValue(NgapIeType_anyOf::eNgapIeType_anyOf::NRPPA_PDU);

  N2InfoContent n2InfoContent = {};
  n2InfoContent.setNgapIeType(ngapIeType);
  n2InfoContent.setNgapData(ngapData);

  NrppaInformation nrppaInformation = {};
  nrppaInformation.setNfId(lmf_nrf_inst->lmf_nf_profile.get_nf_instance_id());
  nrppaInformation.setNrppaPdu(n2InfoContent);

  N2InformationClass n2InformationClass = {};
  n2InformationClass.setEnumValue(
      N2InformationClass_anyOf::eN2InformationClass_anyOf::NRPPA);
  N2InfoContainer n2InfoContainer = {};
  n2InfoContainer.setN2InformationClass(n2InformationClass);
  n2InfoContainer.setNrppaInfo(nrppaInformation);

  N2InformationTransferReqData n2InformationTransferReqData;
  n2InformationTransferReqData.setN2Information(n2InfoContainer);
  if (globalRanNodeList.size() > 0) {
    Logger::lmf_app().debug(
        "non_ue_n2_message_transfer: globalRanNodeList set, send to %d gNBs",
        globalRanNodeList.size());
    n2InformationTransferReqData.setGlobalRanNodeList(globalRanNodeList);
  } else {
    Logger::lmf_app().debug(
        "non_ue_n2_message_transfer: globalRanNodeList not set, send to all "
        "gNBs using ratSelector");
    n2InformationTransferReqData.setRatSelector("NR");
  }

  nlohmann::json n2InformationTransferReqData_json;
  to_json(n2InformationTransferReqData_json, n2InformationTransferReqData);

  std::string body      = {};
  std::string json_part = {};
  json_part             = n2InformationTransferReqData_json.dump();

  mime_parser::create_multipart_related_content(
      body, json_part, CURL_MIME_BOUNDARY, nrppaMsgHex,
      multipart_related_content_part_e::NGAP);

  // avoid
  // [error] extract_nrppaTxnId2Supi: unknown nrppa txn id:0
  // prepare receiving n2 notification before sending request,
  // because if the amf/gnb is fast the nrppa response
  // can be received before NON_UE_N2_TRANSFER_INITIATED
  if (auto const& [iter, inserted] =
          this->nrppa_tId.try_emplace(txnId, procedureCode);
      !inserted) {
    throwHttpError(
        "non-ue n2 message transfer: "s,
        "nrppa id "s + std::to_string(txnId) + " reuse"s);
  }
  lmf_app_inst->insert_nrppaTxnId2supi(txnId, this->supi);

  // Send HTTP request
  oai::http::request http_request =
      http_client_inst->prepare_multipart_request(amf_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);
  response = http_response.body;

  Logger::lmf_app().info("Response from AMF: %s", response);

  // N2InformationTransferRspData;
  // N2InformationTransferError
  // N2InformationTransferResult

  auto const& rspData_json = nlohmann::json::parse(response);
  if ((rspData_json.contains("cause") &&
       (rspData_json["cause"] != "NON_UE_N2_TRANSFER_INITIATED")) ||
      (rspData_json.contains("result") &&
       (rspData_json["result"] != "N2_INFO_TRANSFER_INITIATED"))) {
    this->nrppa_tId.erase(txnId);
    lmf_app_inst->nrppa_tid_gen.free_uid(txnId);

    auto const& title = "non-ue-n2-message transfer failed"s;
    auto const& cause =
        rspData_json.contains("cause") ?
            non_ue_n2_message_transfer_cause_e2str[rspData_json["cause"]] :
            "no cause"s;
    auto const& detail = "supi: '"s + this->supi + "': cause: "s + cause;
    throwHttpError(title, detail);
  }

  return true;
}

//------------------------------------------------------------------------------
template<typename T>
T LocationDetermination::wait_for_notification(
    std::string const& kind, NRPPATransactionID_t const& tId,
    std::promise<T>& p, std::chrono::milliseconds const& wait_ms) {
  Logger::lmf_app().info(
      "waiting %dms for %s notification for supi %s, tId: %d", wait_ms.count(),
      kind, this->supi, tId);

  auto const& start = std::chrono::steady_clock::now();
  auto f            = p.get_future();
  switch (auto const& rc = f.wait_for(wait_ms); rc) {
    case std::future_status::timeout: {
      this->throwHttpError(
          kind + " notification timeout"s,
          "waited "s + std::to_string(wait_ms.count()) + "ms"s);
    } break;

    case std::future_status::ready: {
      Logger::lmf_app().info(
          kind + " notifiaction received for supi: %s waiting %dms"s,
          this->supi, elapsed_ms(start));
    } break;

    default:
      this->throwHttpError(
          kind,
          "unhandled future_status: "s + std::to_string(static_cast<int>(rc)));
  }
  return f.get();
}

//------------------------------------------------------------------------------
LocationDetermination::pos_info_res
LocationDetermination::positioning_information_request() {
  auto const& tId = lmf_app_inst->nrppa_tid_gen.get_uid();
  Logger::lmf_app().info("positioning_information_request: tId: %d", tId);
  auto initiatingMessage =
      (InitiatingMessage_t*) malloc(sizeof(InitiatingMessage_t));
  *initiatingMessage = InitiatingMessage_t{
      .procedureCode      = ProcedureCode_id_positioningInformationExchange,
      .criticality        = Criticality_reject,
      .nrppatransactionID = tId,
      .value =
          {.present =
               InitiatingMessage__value_PR_PositioningInformationRequest},
  };
  auto ies = &initiatingMessage->value.choice.PositioningInformationRequest
                  .protocolIEs.list;

  auto requestedSRSTransmissionCharacteristics =
      (PositioningInformationRequest_IEs_t*) malloc(
          sizeof(PositioningInformationRequest_IEs_t));
  *requestedSRSTransmissionCharacteristics = PositioningInformationRequest_IEs_t{
      .id          = ProtocolIE_ID_id_RequestedSRSTransmissionCharacteristics,
      .criticality = Criticality_ignore,
      .value =
          {
              .present =
                  PositioningInformationRequest_IEs__value_PR_RequestedSRSTransmissionCharacteristics,
              .choice =
                  {
                      .RequestedSRSTransmissionCharacteristics =
                          {
                              .resourceType =
                                  RequestedSRSTransmissionCharacteristics__resourceType_aperiodic,
                              .bandwidth =
                                  {
                                      .present = BandwidthSRS_PR_fR1,
                                      .choice =
                                          {.fR1 = BandwidthSRS__fR1_kHz100},
                                  },
                          },
                  },
          },
  };
  ASN_SEQUENCE_ADD(ies, requestedSRSTransmissionCharacteristics);

  auto nrppaPdu = (NRPPA_PDU_t*) malloc(sizeof(NRPPA_PDU_t));
  *nrppaPdu     = NRPPA_PDU_t{
      .present = NRPPA_PDU_PR_initiatingMessage,
      .choice  = {.initiatingMessage = initiatingMessage},
  };

  this->positioning_information_response = {};
  this->n1_n2_message_transfer(
      share_nrppa_pdu(nrppaPdu), tId,
      ProcedureCode_id_positioningInformationExchange);
  return this->wait_for_notification(
      "positioning information", tId, this->positioning_information_response,
      lmf_cfg.positioning_wait_ms);
}

//------------------------------------------------------------------------------
void LocationDetermination::collectResult(
    Gnb const& gnb, TRP_MeasurementResponseList_t const& trpMeasurementList) {
  std::unique_lock lock(this->m_result);
  for (auto const& trpMeasurement : trpMeasurementList) {
    auto const& trpId = trpMeasurement->tRP_ID;
    for (auto const& measurement : trpMeasurement->measurementResult) {
      if (measurement->measuredResultsValue.present ==
          TrpMeasuredResultsValue_PR_uL_RTOA) {
        auto const& uLRTOAmeas =
            measurement->measuredResultsValue.choice.uL_RTOA->uLRTOAmeas;
        auto const& choice = uLRTOAmeas.choice;
        auto const& key    = uLRTOAmeas.present;
        auto const& val    = key == ULRTOAMeas_PR_k0 ? choice.k0 :
                             key == ULRTOAMeas_PR_k1 ? choice.k1 :
                             key == ULRTOAMeas_PR_k2 ? choice.k2 :
                             key == ULRTOAMeas_PR_k3 ? choice.k3 :
                             key == ULRTOAMeas_PR_k4 ? choice.k4 :
                                                       choice.k5;
        auto const& msg    = ((this->result.count(gnb.id) > 0) &&
                           (this->result[gnb.id].count(trpId) > 0) &&
                           (this->result[gnb.id][trpId].count(key) > 0)) ?
                                 "replace" :
                                 "insert";
        Logger::lmf_app().info(
            "measurement: gnbId: 0x%x, trpId: %d %s key k%d = %d", gnb.id,
            trpId, msg, key - 1, val);
        this->result[gnb.id][trpId][key] = val;
      }
    }
  }
}

//------------------------------------------------------------------------------
LocationDetermination::mmr_res LocationDetermination::measurement_request(
    Gnb const& gnb, SRSConfiguration_t const& srsConfigurationUE) {
  auto const& tId               = lmf_app_inst->nrppa_tid_gen.get_uid();
  auto const& globalRanNodeList = std::vector{gnb.ncgi};
  auto const& trpIdRng          = boost::adaptors::keys(gnb.trp);
  auto const& trpIds            = std::set(trpIdRng.begin(), trpIdRng.end());

  Logger::lmf_app().info("measurement request: tId: %d", tId);

  auto initiatingMessage =
      (InitiatingMessage_t*) malloc(sizeof(InitiatingMessage_t));
  *initiatingMessage = InitiatingMessage_t{
      .procedureCode      = ProcedureCode_id_Measurement,
      .criticality        = Criticality_reject,
      .nrppatransactionID = tId,
      .value = {.present = InitiatingMessage__value_PR_MeasurementRequest},
  };
  auto ies =
      &initiatingMessage->value.choice.MeasurementRequest.protocolIEs.list;

  auto lmfMeasurementIdIe =
      (MeasurementRequest_IEs_t*) malloc(sizeof(MeasurementRequest_IEs_t));
  *lmfMeasurementIdIe = MeasurementRequest_IEs_t{
      .id          = ProtocolIE_ID_id_LMF_Measurement_ID,
      .criticality = Criticality_reject,
      .value =
          {
              .present = MeasurementRequest_IEs__value_PR_Measurement_ID,
              .choice  = {.Measurement_ID = this->measurementId},
          },
  };
  ASN_SEQUENCE_ADD(ies, lmfMeasurementIdIe);

  auto trpMeasurementRequestListIe =
      (MeasurementRequest_IEs_t*) malloc(sizeof(MeasurementRequest_IEs_t));
  *trpMeasurementRequestListIe = {
      .id          = ProtocolIE_ID_id_TRP_MeasurementRequestList,
      .criticality = Criticality_reject,
      .value =
          {
              .present =
                  MeasurementRequest_IEs__value_PR_TRP_MeasurementRequestList,
          },
  };
  auto trpMeasurementRequestList = &trpMeasurementRequestListIe->value.choice
                                        .TRP_MeasurementRequestList.list;
  for (auto const& trpId : trpIds) {
    auto trpMeasurementRequestItem = (TRP_MeasurementRequestItem_t*) malloc(
        sizeof(TRP_MeasurementRequestItem_t));
    *trpMeasurementRequestItem = TRP_MeasurementRequestItem_t{
        .tRP_ID = trpId,
    };
    ASN_SEQUENCE_ADD(trpMeasurementRequestList, trpMeasurementRequestItem);
  }
  ASN_SEQUENCE_ADD(ies, trpMeasurementRequestListIe);

  auto reportCharacteristics =
      (MeasurementRequest_IEs_t*) malloc(sizeof(MeasurementRequest_IEs_t));
  *reportCharacteristics = MeasurementRequest_IEs_t{
      .id          = ProtocolIE_ID_id_ReportCharacteristics,
      .criticality = Criticality_reject,
      .value =
          {
              .present = MeasurementRequest_IEs__value_PR_ReportCharacteristics,
              .choice =
                  {
                      .ReportCharacteristics = ReportCharacteristics_onDemand,
                  },
          },
  };
  ASN_SEQUENCE_ADD(ies, reportCharacteristics);

  auto srsConfigurationIE =
      (MeasurementRequest_IEs_t*) malloc(sizeof(MeasurementRequest_IEs_t));
  *srsConfigurationIE = MeasurementRequest_IEs_t{
      .id          = ProtocolIE_ID_id_SRSConfiguration,
      .criticality = Criticality_ignore,
      .value =
          {
              .present = MeasurementRequest_IEs__value_PR_SRSConfiguration,
              .choice =
                  {
                      .SRSConfiguration = srsConfigurationUE,
                  },
          },
  };
  auto ueSrsConfigurationShared =
      &srsConfigurationIE->value.choice.SRSConfiguration;
  ASN_SEQUENCE_ADD(ies, srsConfigurationIE);

  auto nrppaPdu = (NRPPA_PDU_t*) malloc(sizeof(NRPPA_PDU_t));
  *nrppaPdu     = NRPPA_PDU_t{
      .present = NRPPA_PDU_PR_initiatingMessage,
      .choice  = {.initiatingMessage = initiatingMessage},
  };

  this->measurement_response = {};  // clear promise
  this->non_ue_n2_message_transfer(
      share_nrppa_pdu(nrppaPdu), tId, ProcedureCode_id_Measurement,
      globalRanNodeList, ueSrsConfigurationShared);

  return this->wait_for_notification(
      "measurement", tId, this->measurement_response,
      lmf_cfg.measurement_wait_ms);
  // nrppaPduMR contain measurement
  // MEASUREMENT RESPONSE ( 9.1.4.2 NRPPa TS 38.455 )
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_measurement_response(
    NrppaPduShared nrppaPdu, MeasurementResponse_t const& measurementResponse) {
  Logger::lmf_app().info("handle measurement response");
  for (auto const& ie : measurementResponse.protocolIEs) {
    if (ie->id == ProtocolIE_ID_id_TRP_MeasurementResponseList &&
        ie->value.present ==
            MeasurementResponse_IEs__value_PR_TRP_MeasurementResponseList) {
      auto const& trpMeasurementList =
          ie->value.choice.TRP_MeasurementResponseList;
      this->measurement_response.set_value(
          std::make_tuple(nrppaPdu, std::cref(trpMeasurementList)));
    }
  }
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_measurement_failure(
    NrppaPduShared nrppaPdu, MeasurementFailure_t const& measurementFailure) {
  auto err = CauseError::parse(
      measurementFailure, MeasurementFailure_IEs__value_PR_Cause);
  this->measurement_response.set_value(err);
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_positioning_information_response(
    NrppaPduShared nrppaPdu, NRPPATransactionID_t const& tId,
    PositioningInformationResponse_t const& positioningInformationResponse) {
  Logger::lmf_app().info("handle positioning information response");
  std::optional<pos_info_res> res;

  for (auto const& positioningInformationIE :
       positioningInformationResponse.protocolIEs) {
    if (positioningInformationIE->id == ProtocolIE_ID_id_SRSConfiguration &&
        positioningInformationIE->value.present ==
            PositioningInformationResponse_IEs__value_PR_SRSConfiguration) {
      auto const& srsCfg =
          positioningInformationIE->value.choice.SRSConfiguration;
      res.emplace(std::make_tuple(nrppaPdu, std::cref(srsCfg)));
    }
  }
  if (!res.has_value()) {
    try {
      throwHttpError(
          "handle_positioning_information_response: srsConfiguration missing",
          "srsConfiguration needed for non-ue measurement request");
    } catch (...) {
      this->positioning_information_response.set_exception(
          std::current_exception());
      throw;
    }
  }
  this->positioning_information_response.set_value(res.value());
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_positioning_information_failure(
    NrppaPduShared nrppaPdu,
    PositioningInformationFailure_t const& positioningInformationFailure) {
  auto err = CauseError::parse(
      positioningInformationFailure,
      PositioningInformationFailure_IEs__value_PR_Cause);
  this->positioning_information_response.set_value(err);
}

//------------------------------------------------------------------------------
// 9.1.1.17 POSITIONING ACTIVATION REQUEST
LocationDetermination::pos_act_res
LocationDetermination::positioning_activation_request() {
  auto const& tId = lmf_app_inst->nrppa_tid_gen.get_uid();
  Logger::lmf_app().info("positioning_activation_request: tId: %d", tId);
  auto initiatingMessage =
      (InitiatingMessage_t*) malloc(sizeof(InitiatingMessage_t));
  *initiatingMessage = InitiatingMessage_t{
      .procedureCode      = ProcedureCode_id_positioningActivation,
      .criticality        = Criticality_reject,
      .nrppatransactionID = tId,
      .value =
          {.present = InitiatingMessage__value_PR_PositioningActivationRequest},
  };
  auto ies = &initiatingMessage->value.choice.PositioningActivationRequest
                  .protocolIEs.list;

  // >Aperiodic
  auto aperiodicSRS = (AperiodicSRS_t*) malloc(sizeof(AperiodicSRS_t));
  *aperiodicSRS     = AperiodicSRS_t{
      .aperiodic = AperiodicSRS__aperiodic_true,
  };
  // CHOICE SRS type
  auto aperiodicSRS_ie = (PositioningActivationRequestIEs_t*) malloc(
      sizeof(PositioningActivationRequestIEs_t));
  *aperiodicSRS_ie = PositioningActivationRequestIEs_t{
      .id          = ProtocolIE_ID_id_SRSType,
      .criticality = Criticality_reject,
      .value =
          {
              .present = PositioningActivationRequestIEs__value_PR_SRSType,
              .choice =
                  {
                      .SRSType =
                          {
                              .present = SRSType_PR_aperiodicSRS,
                              .choice =
                                  {
                                      .aperiodicSRS = aperiodicSRS,
                                  },
                          },
                  },
          },
  };
  ASN_SEQUENCE_ADD(ies, aperiodicSRS_ie);
#if 0
  // >Semi-persistent
  auto semipersistentSRS =
      (SemipersistentSRS_t*) malloc(sizeof(SemipersistentSRS_t));
  *semipersistentSRS = SemipersistentSRS_t{
      .sRSResourceSetID = 1,
  };
  // CHOICE SRS type
  auto semipersistentSRS_ie = (PositioningActivationRequestIEs_t*) malloc(
      sizeof(PositioningActivationRequestIEs_t));
  *semipersistentSRS_ie = PositioningActivationRequestIEs_t{
      .id          = ProtocolIE_ID_id_SRSType,
      .criticality = Criticality_reject,
      .value =
          {
              .present = PositioningActivationRequestIEs__value_PR_SRSType,
              .choice =
                  {
                      .SRSType =
                          {
                              .present = SRSType_PR_semipersistentSRS,
                              .choice =
                                  {
                                      .semipersistentSRS = semipersistentSRS,
                                  },
                          },
                  },
          },
  };
  ASN_SEQUENCE_ADD(ies, semipersistentSRS_ie);
#endif
  auto nrppaPdu = (NRPPA_PDU_t*) malloc(sizeof(NRPPA_PDU_t));
  *nrppaPdu     = NRPPA_PDU_t{
      .present = NRPPA_PDU_PR_initiatingMessage,
      .choice  = {.initiatingMessage = initiatingMessage},
  };
  this->positioning_activation_response = {};
  this->n1_n2_message_transfer(
      share_nrppa_pdu(nrppaPdu), tId, ProcedureCode_id_positioningActivation);
  return this->wait_for_notification(
      "positionong activation", tId, this->positioning_activation_response,
      lmf_cfg.positioning_wait_ms);
}

//------------------------------------------------------------------------------
// 9.1.1.20 POSITIONING DEACTIVATION
bool LocationDetermination::positioning_deactivation_request() {
  auto const& tId = lmf_app_inst->nrppa_tid_gen.get_uid();

  auto initiatingMessage =
      (InitiatingMessage_t*) malloc(sizeof(InitiatingMessage_t));
  *initiatingMessage = InitiatingMessage_t{
      .procedureCode      = ProcedureCode_id_positioningDeactivation,
      .criticality        = Criticality_reject,
      .nrppatransactionID = tId,
      .value = {.present = InitiatingMessage__value_PR_PositioningDeactivation},
  };
  auto ies =
      &initiatingMessage->value.choice.PositioningDeactivation.protocolIEs.list;

  // >Release ALL
  auto positioningDeactivationIe = (PositioningDeactivationIEs_t*) malloc(
      sizeof(PositioningDeactivationIEs_t));
  *positioningDeactivationIe = PositioningDeactivationIEs_t{
      .id          = ProtocolIE_ID_id_AbortTransmission,
      .criticality = Criticality_ignore,
      .value =
          {
              .present = PositioningDeactivationIEs__value_PR_AbortTransmission,
              .choice =
                  {
                      .AbortTransmission =
                          {
                              .present = AbortTransmission_PR_releaseALL,
                              .choice =
                                  {
                                      .releaseALL = true,  // meaningless
                                  },
                          },
                  },
          },
  };
  ASN_SEQUENCE_ADD(ies, positioningDeactivationIe);

  auto nrppaPdu = (NRPPA_PDU_t*) malloc(sizeof(NRPPA_PDU_t));
  *nrppaPdu     = NRPPA_PDU_t{
      .present = NRPPA_PDU_PR_initiatingMessage,
      .choice  = {.initiatingMessage = initiatingMessage},
  };

  this->n1_n2_message_transfer(
      share_nrppa_pdu(nrppaPdu), tId, ProcedureCode_id_positioningDeactivation);
  // no success/failure notifiaction defined, nothing to wait for
  this->nrppa_tId.erase(tId);

  return true;
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_positioning_activation_response(
    NrppaPduShared nrppaPdu, NRPPATransactionID_t const& tId,
    PositioningActivationResponse_t const& positioningActivationResponse) {
  Logger::lmf_app().info("handle positioning activation response");
  this->positioning_activation_response.set_value({nrppaPdu});
}

//------------------------------------------------------------------------------
void LocationDetermination::handle_positioning_activation_failure(
    NrppaPduShared nrppa,
    PositioningActivationFailure_t const& positioningActivationFailure) {
  auto err = CauseError::parse(
      positioningActivationFailure,
      PositioningActivationFailureIEs__value_PR_Cause);
  this->positioning_activation_response.set_value(err);
}

//------------------------------------------------------------------------------
void LocationDetermination::throwHttpError(
    std::string const& title, std::string const& detail,
    Pistache::Http::Code const& code) {
  oai::lmf::api::lmf_sbi_helper::throwHttpError(
      title, detail, this->supi, code);
}

//------------------------------------------------------------------------------
nlohmann::json LocationDetermination::compute_location(
    std::map<oai::lmf::app::GnbId, oai::lmf::app::Gnb> const& gnbs) {
  std::vector<double> toas;
  std::vector<std::array<double, 3>> trp_pos;
  uint32_t Tc_inv   = 4096 * 480000;
  uint16_t K        = 1;
  uint32_t T_inv    = Tc_inv / (1 << K);
  uint32_t T_ns_inv = 1e9;

  for (auto const& [gnbId, trp] : this->result) {
    if (gnbs.count(gnbId) == 0) {
      Logger::lmf_app().warn("unknown gnbId: %d", gnbId);
      continue;
    }
    auto const gnb = gnbs.at(gnbId);
    for (auto const& [trpId, uLRTOAmeas] : trp) {
      if (gnb.trp.count(trpId) == 0) {
        Logger::lmf_app().warn(
            "no such trpId: %d attached to gnbId: %d", trpId, gnbId);
        continue;
      }
      auto const& trp             = gnb.trp.at(trpId);
      static constexpr auto units = std::array{"mm", "cm", "dm"};
      auto const& unit = units.at(trp.relativeCartesianLocation.xYZunit);

      trp_pos.push_back(
          {static_cast<double>(trp.relativeCartesianLocation.xvalue),
           static_cast<double>(trp.relativeCartesianLocation.yvalue),
           static_cast<double>(trp.relativeCartesianLocation.zvalue)});

      for (auto const& [k, v] : uLRTOAmeas) {
        toas.push_back((v - 492512) * T_ns_inv / T_inv);
        Logger::lmf_app().debug(
            "gnbId: %d, trpId: %d, trpRelCartLoc(x: %d%s, y: %d%s, z: %d%s), "
            "k%d: %d",
            gnbId, trpId, trp.relativeCartesianLocation.xvalue, unit,
            trp.relativeCartesianLocation.yvalue, unit,
            trp.relativeCartesianLocation.zvalue, unit, k - 1, v);
      }
    }
  }

  // Reference ToA index (assuming the first TRP as the reference)
  int ref_toa_idx = 0;
  std::vector<double> tdoa_ns(toas.size() - 1);
  int idx = 0;

  // Calculate TDoA values relative to the reference TRP
  for (size_t i = 0; i < toas.size(); ++i) {
    if (i == ref_toa_idx) continue;  // Skip the reference TRP
    tdoa_ns[idx] = (toas[i] - toas[ref_toa_idx]);
    ++idx;
  }

  // Debug output for TDoA values
  std::cout << "[pos_est] TDoA Values:" << std::endl;
  for (const auto& tau : tdoa_ns) {
    std::cout << "TDoA: " << tau << " nsec" << std::endl;
  }

  // Speed of light in meters per nanosecond
  const double SPEED_OF_LIGHT_NS = 0.3;

  // Convert TDoA values from nanoseconds to meters
  double dd_estimated[7];
  for (int i = 0; i < 7; i++) {
    dd_estimated[i] = tdoa_ns[i] * SPEED_OF_LIGHT_NS;
  }

  // Debug output for dd_estimated values
  std::cout << "[pos_est] dd_estimated Values:" << std::endl;
  for (const auto& dd : dd_estimated) {
    std::cout << "dd_estimated: " << dd << " meters" << std::endl;
  }
  // Convert trp_pos to a C-style array
  double trp_pos_array[trp_pos.size()][3];
  for (size_t i = 0; i < trp_pos.size(); ++i) {
    for (size_t j = 0; j < 3; ++j) {
      trp_pos_array[i][j] = trp_pos[i][j];
    }
  }

  // Estimated position array
  double pos_est[2]     = {0.0, 0.0};
  int dd_estimated_size = sizeof(dd_estimated) / sizeof(dd_estimated[0]);
  // Perform LLS to estimate position
  try {
    lls_estimation(
        trp_pos_array, trp_pos.size(), dd_estimated, dd_estimated_size,
        pos_est);
    std::cout << "[pos_est] Estimated Position: x = " << pos_est[0]
              << ", y = " << pos_est[1] << std::endl;
  } catch (const std::exception& e) {
    Logger::lmf_app().error("Error in LLS estimation: %s", e.what());
    return nlohmann::json{
        {"error", "Failed to compute location due to LLS estimation error"}};
  }
  SupportedGADShapes supportedGADShapes;
  supportedGADShapes.setEnumValue(
      SupportedGADShapes_anyOf::eSupportedGADShapes_anyOf::POINT);

  UncertaintyEllipse uncertaintyEllipse;
  uncertaintyEllipse.setSemiMajor(0.0);
  uncertaintyEllipse.setSemiMinor(0.0);
  uncertaintyEllipse.setOrientationMajor(180);

  oai::model::lmf::GeographicalCoordinates geographicalCoordinates;
  geographicalCoordinates.setLat(0.0);
  geographicalCoordinates.setLon(0.0);

  GeographicArea geographicArea;
  geographicArea.setShape(supportedGADShapes);
  geographicArea.setPoint(geographicalCoordinates);
  geographicArea.setUncertaintyEllipse(uncertaintyEllipse);
  geographicArea.setConfidence(100);

  LocationData locationData;
  locationData.setLocationEstimate(geographicArea);

  nlohmann::json j;
  j["localLocationEstimate"]["shape"]                           = "POINT";
  j["localLocationEstimate"]["localOrigin"]["coordinateId"]     = "string";
  j["localLocationEstimate"]["localOrigin"]["point"]["lon"]     = 180;
  j["localLocationEstimate"]["localOrigin"]["point"]["lat"]     = 90;
  j["localLocationEstimate"]["point"]["x"]                      = pos_est[0];
  j["localLocationEstimate"]["point"]["y"]                      = pos_est[1];
  j["localLocationEstimate"]["point"]["z"]                      = 1.5;
  j["localLocationEstimate"]["uncertaintyEllipse"]["semiMajor"] = 0;
  j["localLocationEstimate"]["uncertaintyEllipse"]["semiMinor"] = 0;
  j["localLocationEstimate"]["uncertaintyEllipse"]["orientationMajor"] = 180;
  j["localLocationEstimate"]["confidence"]                             = 100;

  return j;  // locationData;
}
