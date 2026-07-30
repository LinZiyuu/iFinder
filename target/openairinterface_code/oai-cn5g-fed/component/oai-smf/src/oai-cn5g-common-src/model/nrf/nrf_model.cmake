# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)

SET(NRF_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf)
set(COMMON_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include_directories(${NRF_MODEL_DIR})

file(GLOB NRF_MODEL_SRC_FILES
        ${NRF_MODEL_DIR}/*.cpp
        ${COMMON_MODEL_DIR}/ProblemDetails.cpp
        ${COMMON_MODEL_DIR}/InvalidParam.cpp
        ${COMMON_MODEL_DIR}/UriScheme.cpp
        ${COMMON_MODEL_DIR}/UriScheme_anyOf.cpp
        ${COMMON_MODEL_DIR}/ChangeItem.cpp
        ${COMMON_MODEL_DIR}/ChangeType.cpp
        ${COMMON_MODEL_DIR}/ChangeType_anyOf.cpp
        ${COMMON_MODEL_DIR}/Tai.cpp
        ${COMMON_MODEL_DIR}/Guami.cpp
        ${COMMON_MODEL_DIR}/PlmnId.cpp
        ${COMMON_MODEL_DIR}/PlmnIdNid.cpp
        ${COMMON_MODEL_DIR}/AccessType.cpp
        ${COMMON_MODEL_DIR}/RatType.cpp
        ${COMMON_MODEL_DIR}/RatType_anyOf.cpp
        ${COMMON_MODEL_DIR}/Snssai.cpp
        ${COMMON_MODEL_DIR}/Helpers.cpp
        ${COMMON_MODEL_DIR}/Ipv6Addr.cpp
        ${COMMON_MODEL_DIR}/Ipv6Prefix.cpp
        ${COMMON_MODEL_DIR}/PduSessionType.cpp
        ${COMMON_MODEL_DIR}/PduSessionType_anyOf.cpp
        ${COMMON_MODEL_DIR}/AtsssCapability.cpp
        ${COMMON_MODEL_DIR}/PatchOperation.cpp
        ${COMMON_MODEL_DIR}/PatchOperation_anyOf.cpp
        ${COMMON_MODEL_DIR}/PatchItem.cpp
        ${COMMON_MODEL_DIR}/AccessTokenErr.cpp
        ${COMMON_MODEL_DIR}/AccessTokenReq.cpp
        ${COMMON_MODEL_DIR}/NFType.cpp
        ${COMMON_MODEL_DIR}/NFType_anyOf.cpp
        ${COMMON_MODEL_DIR}/TransportProtocol.cpp
        ${COMMON_MODEL_DIR}/TransportProtocol_anyOf.cpp
        # dependencies from ComplexQuery
        ${COMMON_MODEL_DIR}/ComplexQuery.cpp
        ${COMMON_MODEL_DIR}/CnfUnit.cpp
        ${COMMON_MODEL_DIR}/DnfUnit.cpp
        ${COMMON_MODEL_DIR}/Atom.cpp  
        ${COMMON_MODEL_DIR}/LinksValueSchema.cpp
        )

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${NRF_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${NRF_MODEL_SRC_FILES}
            )
endif()
