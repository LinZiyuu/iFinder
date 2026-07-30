# SPDX-License-Identifier: LicenseRef-CSSL-1.0


SET(NSSF_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nssf)
set(COMMON_MODEL_SRC_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include(${COMMON_MODEL_SRC_DIR}/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)


include_directories(${NSSF_MODEL_DIR})

file(GLOB NSSF_MODEL_SRC_FILES
    ${NSSF_MODEL_DIR}/*.cpp
    ${COMMON_MODEL_DIR}/AccessTokenErr.cpp
    ${COMMON_MODEL_DIR}/AccessTokenReq.cpp
    ${COMMON_MODEL_DIR}/ExtSnssai.cpp
    ${COMMON_MODEL_DIR}/Helpers.cpp
    ${COMMON_MODEL_DIR}/InvalidParam.cpp
    ${COMMON_MODEL_DIR}/NFType.cpp
    ${COMMON_MODEL_DIR}/NFType_anyOf.cpp
    ${COMMON_MODEL_DIR}/ProblemDetails.cpp
    ${COMMON_MODEL_DIR}/PatchItem.cpp
    ${COMMON_MODEL_DIR}/PatchOperation.cpp
    ${COMMON_MODEL_DIR}/PatchOperation_anyOf.cpp
    ${COMMON_MODEL_DIR}/PlmnIdNid.cpp
    ${COMMON_MODEL_DIR}/SdRange.cpp
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${NSSF_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${NSSF_MODEL_SRC_FILES}
            )
endif()
