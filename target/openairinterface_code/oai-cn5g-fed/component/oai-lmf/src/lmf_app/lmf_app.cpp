/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_app.hpp"

#include <unistd.h>

#include <boost/format.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/range/irange.hpp>
#include <chrono>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <thread>

#include "3gpp_29.500.h"
#include "3gpp_29.518.h"
#include "conversions.hpp"
#include "lmf_nrf.hpp"
#include "logger.hpp"
#include "mime_parser.hpp"
// model
#include "GlobalRanNodeId.h"
#include "LocationData.h"
#include "N1MessageClass.h"
#include "N1MessageContainer.h"
#include "N1N2MessageTransferReqData.h"
#include "N1N2MessageTransferRspData.h"
#include "N2InformationNotification.h"
#include "N2InformationTransferReqData.h"
#include "ProblemDetails.h"
#include "RefToBinaryData.h"
#include "UeN1N2InfoSubscriptionCreateData.h"
#include "UeN1N2InfoSubscriptionCreatedData.h"
// nrppa
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "TRP-MeasurementResponseItem.h"
#include "TRPInformationItem.h"
#include "TRPItem.h"
#include "TrpMeasuredResultsValue.h"
#include "TrpMeasurementResultItem.h"
#include "UL-RTOAMeasurement.h"
#include "ULRTOAMeas.h"
#include "UnsuccessfulOutcome.h"
// do not include model GeographicalCoordinates.h
#include "../nrppa/GeographicalCoordinates.h"
#include "CoordinateID.h"
#include "TRPPositionDefinitionType.h"
#include "TRPPositionReferenced.h"
#include "lmf_sbi_helper.hpp"

using namespace std;
using namespace oai::lmf::app;
using namespace oai::model::lmf;
using namespace oai::lmf::config;
using namespace std::chrono_literals;

lmf_nrf* lmf_nrf_inst = nullptr;

// provides for asn container.list.array range based for loops
// for (auto const& xyzIE : xyzResponse.protocolIEs) {
template<typename T>
auto begin(T const& container) {
  return container.list.array;
}

template<typename T>
auto end(T const& container) {
  return container.list.array + container.list.count;
}

//------------------------------------------------------------------------------
lmf_app::lmf_app(const std::string& config_file, lmf_event& ev)
    : event_sub(ev) {}

//------------------------------------------------------------------------------
lmf_app::~lmf_app() {
  if (lmf_nrf_inst) {
    delete lmf_nrf_inst;
    lmf_nrf_inst = nullptr;
  }
  Logger::lmf_app().debug("Delete LMF_APP instance...");
}

//------------------------------------------------------------------------------
bool lmf_app::start() {
  Logger::lmf_app().startup("Starting...");
  // Create NRF instance and register to NRF if needed
  if (lmf_cfg.register_nrf) {
    try {
      lmf_nrf_inst = new lmf_nrf(event_sub);
      Logger::lmf_app().info("NRF TASK Created ");
      // Register to NRF
      lmf_nrf_inst->register_to_nrf();
    } catch (std::exception& e) {
      Logger::lmf_app().error("Cannot create NRF TASK: %s", e.what());
      return false;
    }
  }
  Logger::lmf_app().startup("Started");
  return true;
}

//------------------------------------------------------------------------------
void lmf_app::stop() {
  if (lmf_nrf_inst and lmf_cfg.register_nrf) {
    lmf_nrf_inst->deregister_to_nrf();
    delete lmf_nrf_inst;
    lmf_nrf_inst = nullptr;
  }
}

//------------------------------------------------------------------------------
void lmf_app::trp_information_request(
    std::shared_ptr<LocationDetermination> const& ctx,
    NRPPATransactionID_t const& nrppatransactionID) {
  Logger::lmf_app().info("TRP information request");

  auto initiatingMessage =
      (InitiatingMessage_t*) malloc(sizeof(InitiatingMessage_t));
  *initiatingMessage = InitiatingMessage_t{
      .procedureCode      = ProcedureCode_id_tRPInformationExchange,
      .criticality        = Criticality_reject,
      .nrppatransactionID = nrppatransactionID,
      .value =
          {
              .present = InitiatingMessage__value_PR_TRPInformationRequest,
              .choice =
                  {
                      .TRPInformationRequest = TRPInformationRequest_t{},
                  },
          },
  };

  auto nrppaPdu = (NRPPA_PDU_t*) malloc(sizeof(NRPPA_PDU_t));
  *nrppaPdu     = NRPPA_PDU_t{
      .present = NRPPA_PDU_PR_initiatingMessage,
      .choice =
          {
              .initiatingMessage = initiatingMessage,
          },
  };

  ctx->non_ue_n2_message_transfer(
      share_nrppa_pdu(nrppaPdu), nrppatransactionID,
      ProcedureCode_id_tRPInformationExchange, {}, nullptr);
}

//------------------------------------------------------------------------------
void lmf_app::trp_information(
    std::shared_ptr<LocationDetermination> const& ctx) {
  std::unique_lock lk{this->cv_m_gnb};

  if (this->gnb.size() > 0) {
    Logger::lmf_app().debug(
        "trp information request: alreadey done: gnbs: %d trps: %d",
        this->gnb.size(), this->numTrps());
    return;
  }

  auto const& tId = this->nrppa_tid_gen.get_uid();
  this->trp_information_request(ctx, tId);

  // lmf_cfg.determine_num_gnb -> return false to wait until trp_info_wait_ms
  this->trp_info_err.clear();
  auto const& pred = [&gnb = this->gnb, &err = this->trp_info_err] {
    if (lmf_cfg.determine_num_gnb) return false;  // wait for timeout
    return (gnb.size() + err.size()) ==
           lmf_cfg.num_gnb;  // stop if cfg'd gnb's recvd
  };
  Logger::lmf_app().debug(
      "trp information request: wait %dms for %s gnb responses",
      lmf_cfg.trp_info_wait_ms.count(),
      lmf_cfg.determine_num_gnb ? "until timeout" :
                                  std::to_string(lmf_cfg.num_gnb));
  auto const& rc = this->cv_gnb.wait_for(lk, lmf_cfg.trp_info_wait_ms, pred);
  ctx->nrppa_tId.erase(tId);
  this->nrppa_tid_gen.free_uid(tId);
  this->erase_nrppaTxnId2Supi(tId);
  if (this->trp_info_err.size() > 0) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "trp information failure",
        "gnb err count: "s + std::to_string(this->trp_info_err.size()));
  }
  if (!lmf_cfg.determine_num_gnb &&
      (!rc || this->gnb.size() < lmf_cfg.num_gnb)) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "trp information request",
        "timeout after "s + std::to_string(lmf_cfg.trp_info_wait_ms.count()) +
            "ms waiting for "s + std::to_string(lmf_cfg.num_gnb) +
            " gnb responses, but received: "s +
            std::to_string(this->gnb.size()));
  }
  Logger::lmf_app().debug(
      "trp information request: received %d gnb responses", this->gnb.size());

  if (this->gnb.size() == 0) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "trp information request"s, "no gnbs available"s);
  }
  if (this->numTrps() == 0) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "trp information request"s, "no trp's available"s);
  }
}

//------------------------------------------------------------------------------
void lmf_app::handle_determine_location(
    const InputData& inputData, nlohmann::json& json_data,
    Pistache::Http::Code& code) {
  auto const& supi = inputData.getSupi();

  auto const& ctx = this->create_lmf_context(supi);
  if (!ctx) {
    auto const& err =
        "Could not create context for supi '"s + supi + "': already exist"s;
    Logger::lmf_app().warn(err);
    ProblemDetails problemDetails;
    problemDetails.setCause("INTERNAL_SERVER_ERROR");
    problemDetails.setStatus(
        oai::common::sbi::http_status_code::INTERNAL_SERVER_ERROR);
    problemDetails.setDetail(err);

    json_data = problemDetails;
    code      = Pistache::Http::Code(problemDetails.getStatus());

    return;
  }

  this->create_non_ue_subscription();
  this->trp_information(ctx);
  this->create_n1n2subscription(supi);

  auto const& res = ctx->positioning_information_request();
  if (std::holds_alternative<CauseError>(res)) {
    auto const& err = std::get<CauseError>(res);
    ctx->throwHttpError("positioning infromation request failure", err.msg());
  }
  auto const& [nrppaPduPIR, ueSrsConfiguration] =
      std::get<LocationDetermination::pos_info_succ>(res);
  // nrppaPduPIR contain position information
  // POSITIONING INFORMATION RESPONSE ( 9.1.1.11 NRPPa TS 38.455 )
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppaPduPIR.get());

  // 5. NRPPa Request UE SRS activation
  // 9.1.1.17 POSITIONING ACTIVATION REQUEST
  auto const& pares = ctx->positioning_activation_request();
  if (std::holds_alternative<CauseError>(pares)) {
    auto const& err = std::get<CauseError>(pares);
    ctx->throwHttpError("positioning activation request failure", err.msg());
  }
  auto const& nrppaPduPA = std::get<LocationDetermination::pos_act_succ>(pares);
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppaPduPA.get());

  for (auto const& [id, gnb] : this->gnb) {
    auto const& res = ctx->measurement_request(gnb, ueSrsConfiguration);

    if (std::holds_alternative<CauseError>(res)) {
      auto const& err = std::get<CauseError>(res);
      ctx->throwHttpError("measurement request failure", err.msg());
    }
    auto const& [nrppaPduMR, trpMeasurementList] =
        std::get<LocationDetermination::mmr_succ>(res);

    // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppaPduMR.get());

    ctx->collectResult(gnb, trpMeasurementList);
  }

  // In positioning_deactivation()
  // openairinterface5g/openair2/LAYER2/NR_MAC_gNB/mac_rrc_dl_handler.c:792
  // Not Implemented
  // ctx->positioning_deactivation_request();

  code                = Pistache::Http::Code::Ok;
  auto const& locData = ctx->compute_location(this->gnb);
  // using hard coded location data as adeel requiered
  // can not use rel16 LocationData here, incompatible with rel17 values
  // LocationData locationData{locData};
  json_data = locData;  // locationData;

  this->del_supi_2_context(supi);

  return;
}

//------------------------------------------------------------------------------
bool lmf_app::_is_supi_2_context(const std::string& supi) const {
  return (supi2ctx.count(supi) > 0) && (supi2ctx.at(supi) != nullptr);
}

//------------------------------------------------------------------------------
bool lmf_app::is_supi_2_context(const string& supi) const {
  std::shared_lock lock(m_supi2ctx);
  return _is_supi_2_context(supi);
}

std::shared_ptr<LocationDetermination> lmf_app::create_lmf_context(
    const string& supi) {
  std::unique_lock lock(m_supi2ctx);

  if (this->_is_supi_2_context(supi)) {
    Logger::lmf_app().warn(
        "create_lmf_context: %s: already exist, remove", supi);
    this->supi2ctx.erase(supi);
  }
  return supi2ctx[supi] = std::make_shared<LocationDetermination>(supi);
}

//------------------------------------------------------------------------------
std::shared_ptr<LocationDetermination> lmf_app::supi_2_context(
    const std::string& supi) const {
  std::shared_lock lock(m_supi2ctx);

  if (!_is_supi_2_context(supi)) {
    return {nullptr};
  }
  return supi2ctx.at(supi);
}

//------------------------------------------------------------------------------
void lmf_app::set_supi_2_context(
    const string& supi, const std::shared_ptr<LocationDetermination>& lc) {
  std::unique_lock lock(m_supi2ctx);
  supi2ctx[supi] = lc;
}

//------------------------------------------------------------------------------
void lmf_app::del_supi_2_context(const string& supi) {
  std::unique_lock lock(m_supi2ctx);
  supi2ctx.erase(supi);
}

//------------------------------------------------------------------------------
void lmf_app::create_n1n2subscription(const std::string& supi) {
  std::unique_lock lock(m_supi2n1n2subs);

  auto const& [iter, inserted] = supi2n1n2subs.try_emplace(supi, supi);
  auto const& subscription     = iter->second;
  Logger::lmf_app().info(
      "n1n2info %s for supi: %s id: %s"s,
      inserted ? "subscription created"s : "already subscribed"s,
      subscription.supi, subscription.id);
}

//------------------------------------------------------------------------------
void oai::lmf::app::lmf_app::release_n1n2subscription(const std::string& supi) {
  std::unique_lock lock(this->m_supi2n1n2subs);

  this->supi2n1n2subs.erase(supi);
}

//------------------------------------------------------------------------------
void oai::lmf::app::lmf_app::release_all_n1n2subscriptions() {
  std::unique_lock lock(m_supi2n1n2subs);

  this->supi2n1n2subs.clear();
}

//------------------------------------------------------------------------------
void lmf_app::create_non_ue_subscription() {
  std::scoped_lock lock(this->m_non_ue_subs);

  if (!this->nonUeN2MessageSubscription) {
    this->nonUeN2MessageSubscription =
        std::make_unique<NonUeN2MessageSubscription>();
    Logger::lmf_app().info("non-ue subscription created");
  } else {
    Logger::lmf_app().debug(
        "non-ue subscription not created: already subscribed");
  }
}

//------------------------------------------------------------------------------
void oai::lmf::app::lmf_app::release_non_ue_subscription() {
  std::scoped_lock lock(this->m_non_ue_subs);

  if (this->nonUeN2MessageSubscription) {
    this->nonUeN2MessageSubscription.reset();
    Logger::lmf_app().info("non-ue subscription deleted");
  } else {
    Logger::lmf_app().debug("non-ue subscription not deleted: already deleted");
  }
}

//------------------------------------------------------------------------------
NRPPATransactionID_t getNrppaTxnId(NrppaPduShared nrppa) {
  switch (nrppa->present) {
    case NRPPA_PDU_PR_initiatingMessage:
      return nrppa->choice.initiatingMessage->nrppatransactionID;
    case NRPPA_PDU_PR_successfulOutcome:
      return nrppa->choice.successfulOutcome->nrppatransactionID;
    case NRPPA_PDU_PR_unsuccessfulOutcome:
      return nrppa->choice.unsuccessfulOutcome->nrppatransactionID;
    default:
      oai::lmf::api::lmf_sbi_helper::throwHttpError(
          "getNrppaTxnId"s, "malformed nrppa message"s);
  }
  return 0;
}

//------------------------------------------------------------------------------
// check 1:1 relationship between procedureCode and value.present
template<typename T, typename U>
static void checkPC(T const& present, U const& expected) {
  if (present->procedureCode != expected) {
    auto const &title  = "handle_nrppa_notification: invalid procedue code"s,
               &ps     = "present: "s + std::to_string(present->procedureCode),
               &es     = "expected: "s + std::to_string(expected),
               &detail = ps + ": "s + es;
    oai::lmf::api::lmf_sbi_helper::throwHttpError(title, detail);
  }
}

//------------------------------------------------------------------------------
template<typename T, typename U, typename V>
static U const& getPR(U const& choice, T const& value, V const& expected) {
  if (value.present != expected) {
    auto const &title  = "handle_nrppa_notification: invalid message"s,
               &ps     = "present: "s + std::to_string(value.present),
               &es     = "expected: "s + std::to_string(expected),
               &detail = ps + ": "s + es;
    oai::lmf::api::lmf_sbi_helper::throwHttpError(title, detail);
  }
  return choice;
}

//------------------------------------------------------------------------------
void lmf_app::handle_trp_information_response(
    NrppaPduShared nrppa, NRPPATransactionID_t const& tId,
    TRPInformationResponse_t const& trpInformation) {
  Logger::lmf_app().debug("trp information received");
  std::scoped_lock lk{this->cv_m_gnb};

  for (auto const& trpInformationIE : trpInformation.protocolIEs) {
    if (trpInformationIE->id == ProtocolIE_ID_id_TRPInformationList) {
      auto const& value              = trpInformationIE->value;
      auto const& trpInformationList = getPR(
          value.choice.TRPInformationList, value,
          TRPInformationResponse_IEs__value_PR_TRPInformationList);
      for (auto const& trpInformationListMember : trpInformationList) {
        auto const& trpId = trpInformationListMember->tRP_ID;
        std::optional<GnbId> gnbId;
        Trp trp;

        for (auto const& trpInformationItem :
             trpInformationListMember->tRPInformation) {
          switch (trpInformationItem->present) {
            case TRPInformationItem_PR_nG_RAN_CGI: {
              auto const& ngRanCgi      = trpInformationItem->choice.nG_RAN_CGI;
              auto const& plmnnIdentity = ngRanCgi->pLMN_Identity;
              if (plmnnIdentity.size != 3) {
                oai::lmf::api::lmf_sbi_helper::throwHttpError(
                    "trp information response",
                    "plmnnIdentity.size != 3: "s +
                        std::to_string(plmnnIdentity.size));
              }

              if (ngRanCgi->nG_RANcell.present == NG_RANCell_PR_nR_CellID) {
                auto const& ngRanCell = ngRanCgi->nG_RANcell.choice.nR_CellID;
                if (ngRanCell.size != 5 || ngRanCell.bits_unused != 4) {
                  oai::lmf::api::lmf_sbi_helper::throwHttpError(
                      "trp information response",
                      "ngRanCell.size != 5: "s +
                          std::to_string(ngRanCell.size) +
                          " || ngRanCell.bits_unused != 4: " +
                          std::to_string(ngRanCell.bits_unused));
                }
                uint64_t nci = 0;
                for (auto i = 0, s = 32; i < 5; ++i, s -= 8) {
                  nci |= static_cast<uint64_t>(ngRanCell.buf[i]) << s;
                }
                nci >>= ngRanCell.bits_unused;
                auto const& cellIdBitCnt = 36 - lmf_cfg.gnb_id_bits_count;
                gnbId.emplace(nci >> cellIdBitCnt);

                if (this->gnb.count(gnbId.value()) == 0) {
                  static auto constexpr d1 = [](auto const& v) constexpr {
                    return v & 0xf;
                  };
                  static auto constexpr d2 = [](auto const& v) constexpr {
                    return v >> 4;
                  };
                  auto const& pb  = plmnnIdentity.buf;
                  auto const& mcc = (boost::format("%0d%0d%0d") % d1(pb[0]) %
                                     d2(pb[0]) % d1(pb[1]))
                                        .str();
                  auto const& mncd3 = d2(pb[1]);
                  auto const& mnc2  = (mncd3 == 0xf);
                  auto const& mnc =
                      mnc2 ? (boost::format("%0d%0d") % d1(pb[2]) % d2(pb[2]))
                                 .str() :
                             (boost::format("%0d%0d%0d") % d1(pb[2]) %
                              d2(pb[2]) % mncd3)
                                 .str();
                  if (mcc.size() > 3) {
                    oai::lmf::api::lmf_sbi_helper::throwHttpError(
                        "trp information response", "invalid mcc: "s + mcc);
                  }
                  if (mnc.size() > (mnc2 ? 2 : 3)) {
                    oai::lmf::api::lmf_sbi_helper::throwHttpError(
                        "trp information response", "invalid mnc: "s + mnc);
                  }

                  PlmnId plmnId;
                  plmnId.setMcc(mcc);
                  plmnId.setMnc(mnc);

                  auto const& gnbValue =
                      (boost::format(
                           lmf_cfg.gnb_id_bits_count <= 24 ? "%06x" : "%08x") %
                       gnbId.value())
                          .str();
                  GNbId gNbId;
                  gNbId.setGNBValue(gnbValue);
                  gNbId.setBitLength(lmf_cfg.gnb_id_bits_count);

                  GlobalRanNodeId globalRanNodeId;
                  globalRanNodeId.setPlmnId(plmnId);
                  globalRanNodeId.setGNbId(gNbId);

                  Logger::lmf_app().info(
                      "trp information: adding gnb with id: 0x%x mcc: %s mnc: "
                      "%s",
                      gnbId.value(), mcc, mnc);

                  if (auto const& [iter, inserted] = this->gnb.try_emplace(
                          gnbId.value(), gnbId.value(), globalRanNodeId);
                      !inserted) {
                    oai::lmf::api::lmf_sbi_helper::throwHttpError(
                        "trp information response",
                        "gnbId: "s + std::to_string(gnbId.value()) +
                            " already inserted"s);
                  }
                }
              } else {
                oai::lmf::api::lmf_sbi_helper::throwHttpError(
                    "trp information response",
                    "TRPInformationItem_PR_nG_RAN_CGI not present, but: "s +
                        std::to_string(ngRanCgi->nG_RANcell.present));
              }

            } break;

            case TRPInformationItem_PR_geographicalCoordinates: {
              auto const& geographicalCoordinates =
                  trpInformationItem->choice.geographicalCoordinates;
              auto const& trpPositionDefinitionType =
                  geographicalCoordinates->tRPPositionDefinitionType;
              switch (trpPositionDefinitionType.present) {
                case TRPPositionDefinitionType_PR_referenced: {
                  auto const& referenced =
                      trpPositionDefinitionType.choice.referenced;
                  auto const& referencePoint = referenced->referencePoint;
                  auto const& referencePointType =
                      referenced->referencePointType;

                  switch (referencePoint.present) {
                    case ReferencePoint_PR_relativeCoordinateID: {
                      trp.relativeCoordinateID =
                          referencePoint.choice.relativeCoordinateID;
                    } break;

                    default:
                      Logger::lmf_app().warn(
                          "trp information: unhandled ReferencePoint_PR: %d",
                          referencePoint.present);
                  }

                  switch (referencePointType.present) {
                    case TRPReferencePointType_PR_tRPPositionRelativeCartesian: {
                      trp.relativeCartesianLocation =
                          *referencePointType.choice
                               .tRPPositionRelativeCartesian;
                    } break;

                    default:
                      Logger::lmf_app().warn(
                          "trp information: unhandled "
                          "TRPReferencePointType_PR: %d",
                          referencePointType.present);
                  }

                } break;

                default:
                  Logger::lmf_app().warn(
                      "trp information: unhandled "
                      "TRPPositionDefinitionType_PR: %d",
                      trpPositionDefinitionType.present);
              }
            } break;

            default:
              Logger::lmf_app().warn(
                  "trp information: unhandled TRPInformationItem_PR: %d",
                  trpInformationItem->present);
          }
        }

        if (gnbId.has_value()) {
          if (this->gnb.at(gnbId.value()).trp.count(trpId) == 0) {
            Logger::lmf_app().info(
                "trp information: adding to gnbId: 0x%x trpId: %d coordID: %d "
                "x: %d y: %d z: %d",
                gnbId.value(), trpId, trp.relativeCoordinateID,
                trp.relativeCartesianLocation.xvalue,
                trp.relativeCartesianLocation.yvalue,
                trp.relativeCartesianLocation.zvalue);
            if (auto const& [iter, inserted] =
                    this->gnb.at(gnbId.value()).trp.try_emplace(trpId, trp);
                !inserted) {
              oai::lmf::api::lmf_sbi_helper::throwHttpError(
                  "trp information response",
                  "trpId: "s + std::to_string(trpId) + " already inserted"s);
            }
          } else {
            oai::lmf::api::lmf_sbi_helper::throwHttpError(
                "trp information response",
                "gnb_id: " + std::to_string(gnbId.value()) + " " +
                    "trp_id: " + std::to_string(trpId) + " not unique");
          }
        } else {
          oai::lmf::api::lmf_sbi_helper::throwHttpError(
              "trp information", "no gnbId");
        }
      }
    }
  }
  this->cv_gnb.notify_one();
}

//------------------------------------------------------------------------------
bool lmf_app::handle_non_ue_n2info_nrppa_notification(NrppaPduShared nrppa) {
  auto const& nrppaTxnId = getNrppaTxnId(nrppa);
  auto const& supi       = this->get_nrppaTxnId2Supi(nrppaTxnId);

  return this->handle_n2info_nrppa_notification(supi, nrppa);
}

//------------------------------------------------------------------------------
// TODO: replace bool retval with exception
// shoult not fail
bool lmf_app::handle_n2info_nrppa_notification(
    std::string supi, NrppaPduShared nrppa) {
  auto ctx = this->supi_2_context(supi);
  if (!ctx) {
    Logger::lmf_server().error("N2InfoNotify: unknown supi: %s", supi);
    return false;
  }

  auto const& tId = getNrppaTxnId(nrppa);

  // TODO
  if (nrppa->present == NRPPA_PDU_PR_initiatingMessage) {
    // don't forget tId handling ctx->nrppa_tId.erase(tId);
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "handle_n2info_nrppa_notification",
        "NRPPA_PDU_PR_initiatingMessage not implemented");
  }

  if (ctx->nrppa_tId.count(tId) != 1) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "handle_n2info_nrppa_notification"s,
        "unknown nrppa transaction id: "s + std::to_string(tId));
  }

  auto const procedureCode = ctx->nrppa_tId.at(tId);
  // with multiple gnb expect multiple trp infos, erase after timeout
  if (procedureCode != ProcedureCode_id_tRPInformationExchange) {
    ctx->nrppa_tId.erase(tId);          // not for incomming/initiating!
    this->nrppa_tid_gen.free_uid(tId);  // for reuse
  }
  // is non-ue but not a broadcast like trp-info
  // TODO: introduce non-ue "was broadcast" switch
  if (procedureCode == ProcedureCode_id_Measurement) {
    this->erase_nrppaTxnId2Supi(tId);
  }

  if (nrppa->present == NRPPA_PDU_PR_unsuccessfulOutcome) {
    auto const& unsuccessfulOutcome = getPR(
        nrppa->choice.unsuccessfulOutcome, *nrppa,
        NRPPA_PDU_PR_unsuccessfulOutcome);
    checkPC(unsuccessfulOutcome, procedureCode);
    switch (procedureCode) {
      case ProcedureCode_id_tRPInformationExchange: {
        std::scoped_lock lk{this->cv_m_gnb};

        auto const& value                 = unsuccessfulOutcome->value;
        auto const& trpInformationFailure = getPR(
            value.choice.TRPInformationFailure, value,
            UnsuccessfulOutcome__value_PR_TRPInformationFailure);
        auto err = CauseError::parse(
            trpInformationFailure, TRPInformationFailure_IEs__value_PR_Cause);
        this->trp_info_err.push_back(err);
        this->cv_gnb.notify_one();
        return true;
      }; break;

      case ProcedureCode_id_positioningInformationExchange: {
        auto const& value                         = unsuccessfulOutcome->value;
        auto const& positioningInformationFailure = getPR(
            value.choice.PositioningInformationFailure, value,
            UnsuccessfulOutcome__value_PR_PositioningInformationFailure);
        ctx->handle_positioning_information_failure(
            nrppa, positioningInformationFailure);
        return true;
      }; break;

      case ProcedureCode_id_positioningActivation: {
        auto const& value                        = unsuccessfulOutcome->value;
        auto const& positioningActivationFailure = getPR(
            value.choice.PositioningActivationFailure, value,
            UnsuccessfulOutcome__value_PR_PositioningActivationFailure);
        ctx->handle_positioning_activation_failure(
            nrppa, positioningActivationFailure);
        return true;
      }; break;

      case ProcedureCode_id_Measurement: {
        auto const& value              = unsuccessfulOutcome->value;
        auto const& measurementFailure = getPR(
            value.choice.MeasurementFailure, value,
            UnsuccessfulOutcome__value_PR_MeasurementFailure);
        ctx->handle_measurement_failure(nrppa, measurementFailure);
        return true;
      }; break;

      default:
        oai::lmf::api::lmf_sbi_helper::throwHttpError(
            "handle_nrppa_notification"s,
            "unsuccessfulOutcome: unhandled procedure code: %d"s +
                std::to_string(procedureCode));
    }
  }

  auto const& successfulOutcome = getPR(
      nrppa->choice.successfulOutcome, *nrppa, NRPPA_PDU_PR_successfulOutcome);
  checkPC(successfulOutcome, procedureCode);
  switch (procedureCode) {
    case ProcedureCode_id_tRPInformationExchange: {
      auto const& value                  = successfulOutcome->value;
      auto const& trpInformationResponse = getPR(
          value.choice.TRPInformationResponse, value,
          SuccessfulOutcome__value_PR_TRPInformationResponse);
      this->handle_trp_information_response(nrppa, tId, trpInformationResponse);
      return true;
    } break;

    case ProcedureCode_id_positioningInformationExchange: {
      auto const& value                          = successfulOutcome->value;
      auto const& positioningInformationResponse = getPR(
          value.choice.PositioningInformationResponse, value,
          SuccessfulOutcome__value_PR_PositioningInformationResponse);
      ctx->handle_positioning_information_response(
          nrppa, tId, positioningInformationResponse);
      return true;
    } break;

    case ProcedureCode_id_Measurement: {
      auto const& value               = successfulOutcome->value;
      auto const& measurementResponse = getPR(
          value.choice.MeasurementResponse, value,
          SuccessfulOutcome__value_PR_MeasurementResponse);
      ctx->handle_measurement_response(nrppa, measurementResponse);
      return true;
    } break;

    case ProcedureCode_id_positioningActivation: {
      auto const& value                         = successfulOutcome->value;
      auto const& positioningActivationResponse = getPR(
          value.choice.PositioningActivationResponse, value,
          SuccessfulOutcome__value_PR_PositioningActivationResponse);
      ctx->handle_positioning_activation_response(
          nrppa, tId, positioningActivationResponse);
      return true;
    } break;

    default:
      oai::lmf::api::lmf_sbi_helper::throwHttpError(
          "handle_nrppa_notification"s,
          "successfulOutcome: unhandled procedure code: %d"s +
              std::to_string(procedureCode));
  }

  auto titel  = "n2info nrppa notifiaction pdu error"s;
  auto detail = "unhandled nrppa  pdu: " + std::to_string(nrppa->present);
  oai::lmf::api::lmf_sbi_helper::throwHttpError(titel, detail);

  return false;
}

//------------------------------------------------------------------------------
NrppaPduShared lmf_app::parse_n2_info_container_nrppa(
    N2InformationNotification const& n2InformationNotification,
    mime_part const& nrppa_part) {
  if (!n2InformationNotification.n2InfoContainerIsSet()) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa", "N2InfoContainer not present");
  }

  auto const& n2InfoContainer = n2InformationNotification.getN2InfoContainer();
  auto const& eN2InformationClass =
      n2InfoContainer.getN2InformationClass().getEnumValue();

  // Check N2 Information Class
  if (eN2InformationClass !=
      N2InformationClass_anyOf::eN2InformationClass_anyOf::NRPPA) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa",
        "N2 Information Class not NRPPA: " +
            std::to_string(static_cast<int>(eN2InformationClass)));
  }

  if (!n2InfoContainer.nrppaInfoIsSet()) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa", "nrppaInfo not present");
  }
  auto const& nrppaInfo = n2InfoContainer.getNrppaInfo();

  if (nrppaInfo.getNfId() != lmf_nrf_inst->lmf_instance_id) {
    Logger::lmf_server().warn(
        "nfId != '%s': '%s'", lmf_nrf_inst->lmf_instance_id,
        nrppaInfo.getNfId());
  }

  auto const& nrppaPdu = nrppaInfo.getNrppaPdu();
  if (!nrppaPdu.ngapIeTypeIsSet()) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa", "ngapIeType not present");
  }

  auto const& eNgapIeType = nrppaPdu.getNgapIeType().getEnumValue();
  if (eNgapIeType != NgapIeType_anyOf::eNgapIeType_anyOf::NRPPA_PDU) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa",
        "ngapIeType not NRPPA_PDU: " +
            std::to_string(static_cast<int>(eNgapIeType)));
  }
  auto const& ngapData = nrppaPdu.getNgapData();
  Logger::lmf_app().debug(
      "parse_n2_info_container_nrppa: content-id: " + ngapData.getContentId());
  if (nrppa_part.content_type != "application/vnd.3gpp.ngap") {
    Logger::lmf_server().warn(
        "content-type != 'application/vnd.3gpp.ngap': '%s'",
        nrppa_part.content_type);
  }

  auto const& nrppa_bin = nrppa_part.body;
  NRPPA_PDU_t* nrppa    = nullptr;
  auto const& rc        = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_NRPPA_PDU, (void**) &nrppa,
      nrppa_bin.c_str(), nrppa_bin.length());
  if (rc.code != RC_OK) {
    ASN_STRUCT_FREE(asn_DEF_NRPPA_PDU, nrppa);
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "parse_n2_info_container_nrppa",
        "asn_decode failed: " + std::to_string(rc.code));
  }
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppa);
  Logger::lmf_server().debug("asn_decode ok, consumed: %d", rc.consumed);

  return share_nrppa_pdu(nrppa);
}

//------------------------------------------------------------------------------
void oai::lmf::app::lmf_app::insert_nrppaTxnId2supi(
    NRPPATransactionID_t const& nrppaTxnId, std::string const& supi) {
  std::unique_lock lock{this->m_nrppaTxnId2supi};
  auto const& [iter, insered] =
      this->nrppaTxnId2supi.try_emplace(nrppaTxnId, supi);
  if (!insered) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "insert_nrppaTxnId2supi",
        "nrppa id "s + std::to_string(nrppaTxnId) + " reuse"s);
  }
}

//------------------------------------------------------------------------------
std::string oai::lmf::app::lmf_app::extract_nrppaTxnId2Supi(
    NRPPATransactionID_t const& nrppaTxnId) {
  std::unique_lock lock{this->m_nrppaTxnId2supi};
  auto const& nh = this->nrppaTxnId2supi.extract(nrppaTxnId);
  if (nh.empty()) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "extract_nrppaTxnId2Supi",
        "unknown nrppa txn id:"s + std::to_string(nrppaTxnId));
  }
  return nh.mapped();
}

std::string oai::lmf::app::lmf_app::get_nrppaTxnId2Supi(
    NRPPATransactionID_t const& nrppaTxnId) {
  std::unique_lock lock{this->m_nrppaTxnId2supi};
  auto const& it = this->nrppaTxnId2supi.find(nrppaTxnId);
  if (it == std::end(this->nrppaTxnId2supi)) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "get_nrppaTxnId2Supi",
        "unknown nrppa txn id:"s + std::to_string(nrppaTxnId));
  }
  return it->second;
}

void oai::lmf::app::lmf_app::erase_nrppaTxnId2Supi(
    NRPPATransactionID_t const& nrppaTxnId) {
  std::unique_lock lock{this->m_nrppaTxnId2supi};
  auto const& it = this->nrppaTxnId2supi.find(nrppaTxnId);
  if (it == std::end(this->nrppaTxnId2supi)) {
    oai::lmf::api::lmf_sbi_helper::throwHttpError(
        "erase_nrppaTxnId2Supi",
        "unknown nrppa txn id:"s + std::to_string(nrppaTxnId));
  }
  this->nrppaTxnId2supi.erase(it);
}
