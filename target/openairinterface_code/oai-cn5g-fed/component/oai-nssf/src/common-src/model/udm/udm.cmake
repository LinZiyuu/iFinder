# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

SET(UDM_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/udm)

set(COMMON_MODEL_SRC_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include_directories(${UDM_MODEL_DIR})

file(GLOB UDM_MODEL_SRC_FILES
    ${UDM_MODEL_DIR}/*.cpp
    ${COMMON_MODEL_DIR}/AccessTokenErr.cpp
    ${COMMON_MODEL_DIR}/AccessTokenReq.cpp
    ${COMMON_MODEL_DIR}/AccessType.cpp
    ${COMMON_MODEL_DIR}/Arp.cpp
    ${COMMON_MODEL_DIR}/Ambr.cpp
    ${COMMON_MODEL_DIR}/AmbrRm.cpp
    ${COMMON_MODEL_DIR}/Area.cpp
    ${COMMON_MODEL_DIR}/AtsssCapability.cpp
    ${COMMON_MODEL_DIR}/BackupAmfInfo.cpp
    ${COMMON_MODEL_DIR}/ChangeItem.cpp   
    ${COMMON_MODEL_DIR}/ChangeType.cpp    
    ${COMMON_MODEL_DIR}/ChangeType_anyOf.cpp    
    ${COMMON_MODEL_DIR}/CoreNetworkType.cpp
    ${COMMON_MODEL_DIR}/CoreNetworkType_anyOf.cpp
    ${COMMON_MODEL_DIR}/DddTrafficDescriptor.cpp
    ${COMMON_MODEL_DIR}/DlDataDeliveryStatus.cpp
    ${COMMON_MODEL_DIR}/DlDataDeliveryStatus_anyOf.cpp
    ${COMMON_MODEL_DIR}/Guami.cpp
    ${COMMON_MODEL_DIR}/Helpers.cpp
    ${COMMON_MODEL_DIR}/InvalidParam.cpp
    ${COMMON_MODEL_DIR}/Ipv6Addr.cpp
    ${COMMON_MODEL_DIR}/Ipv6Prefix.cpp
    ${COMMON_MODEL_DIR}/NFType.cpp
    ${COMMON_MODEL_DIR}/NFType_anyOf.cpp
    ${COMMON_MODEL_DIR}/NotifyItem.cpp
    ${COMMON_MODEL_DIR}/PatchItem.cpp
    ${COMMON_MODEL_DIR}/PatchOperation.cpp
    ${COMMON_MODEL_DIR}/PatchOperation_anyOf.cpp
    ${COMMON_MODEL_DIR}/PduSessionType.cpp
    ${COMMON_MODEL_DIR}/PduSessionType_anyOf.cpp    
    ${COMMON_MODEL_DIR}/PlmnId.cpp
    ${COMMON_MODEL_DIR}/PlmnIdNid.cpp
    ${COMMON_MODEL_DIR}/PreemptionCapability.cpp
    ${COMMON_MODEL_DIR}/PreemptionCapability_anyOf.cpp
    ${COMMON_MODEL_DIR}/PreemptionVulnerability.cpp
    ${COMMON_MODEL_DIR}/PreemptionVulnerability_anyOf.cpp
    ${COMMON_MODEL_DIR}/ProblemDetails.cpp
    ${COMMON_MODEL_DIR}/OdbPacketServices.cpp
    ${COMMON_MODEL_DIR}/OdbPacketServices_anyOf.cpp
    ${COMMON_MODEL_DIR}/RatType.cpp
    ${COMMON_MODEL_DIR}/RatType_anyOf.cpp
    ${COMMON_MODEL_DIR}/Snssai.cpp
    ${COMMON_MODEL_DIR}/SscMode.cpp
    ${COMMON_MODEL_DIR}/SscMode_anyOf.cpp
    ${COMMON_MODEL_DIR}/SubscribedDefaultQos.cpp
    ${COMMON_MODEL_DIR}/Tai.cpp
    ${COMMON_MODEL_DIR}/TraceData.cpp
    ${COMMON_MODEL_DIR}/TraceDepth.cpp
    ${COMMON_MODEL_DIR}/TraceDepth_anyOf.cpp
    ${COMMON_MODEL_DIR}/UpSecurity.cpp
    ${COMMON_MODEL_DIR}/UpIntegrity.cpp
    ${COMMON_MODEL_DIR}/UpIntegrity_anyOf.cpp
    ${COMMON_MODEL_DIR}/UpConfidentiality.cpp    
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${UDM_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${UDM_MODEL_SRC_FILES}
            )
endif()
