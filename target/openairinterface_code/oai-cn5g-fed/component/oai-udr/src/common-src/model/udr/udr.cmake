# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(UDR_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/udr)
set(COMMON_MODEL_SRC_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include(${COMMON_MODEL_SRC_DIR}/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)


include_directories(${UDR_MODEL_DIR})

file(GLOB UDR_MODEL_SRC_FILES
    ${UDR_MODEL_DIR}/*.cpp
    ${COMMON_MODEL_DIR}/*.cpp
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${UDR_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${UDR_MODEL_SRC_FILES}
            )
endif()
