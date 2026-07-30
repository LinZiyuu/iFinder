# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

SET(AUSF_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/ausf)

set(COMMON_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include_directories(${AUSF_MODEL_DIR})

file(GLOB AUSF_MODEL_SRC_FILES
    ${AUSF_MODEL_DIR}/*.cpp
    ${COMMON_MODEL_DIR}/Helpers.cpp
    ${COMMON_MODEL_DIR}/InvalidParam.cpp
    ${COMMON_MODEL_DIR}/Ipv6Addr.cpp
    ${COMMON_MODEL_DIR}/Link.cpp
    ${COMMON_MODEL_DIR}/LinksValueSchema.cpp
    ${COMMON_MODEL_DIR}/PatchItem.cpp
    ${COMMON_MODEL_DIR}/PatchOperation.cpp
    ${COMMON_MODEL_DIR}/PatchOperation_anyOf.cpp
    ${COMMON_MODEL_DIR}/TraceData.cpp
    ${COMMON_MODEL_DIR}/TraceDepth.cpp
    ${COMMON_MODEL_DIR}/TraceDepth_anyOf.cpp
    ${COMMON_MODEL_DIR}/ProblemDetails.cpp
    ${COMMON_MODEL_DIR}/AccessTokenErr.cpp
    ${COMMON_MODEL_DIR}/AccessTokenReq.cpp
    ${COMMON_MODEL_DIR}/NFType.cpp
    ${COMMON_MODEL_DIR}/NFType_anyOf.cpp
    ${COMMON_MODEL_DIR}/PlmnId.cpp
    ${COMMON_MODEL_DIR}/PlmnIdNid.cpp
    ${COMMON_MODEL_DIR}/Snssai.cpp
    ${COMMON_MODEL_DIR}/Tai.cpp
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${AUSF_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${AUSF_MODEL_SRC_FILES}
            )
endif()
