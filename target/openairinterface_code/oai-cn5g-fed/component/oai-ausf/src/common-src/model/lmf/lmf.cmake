# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(LMF_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/lmf)
set(COMMON_MODEL_SRC_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include(${COMMON_MODEL_SRC_DIR}/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)


include_directories(${LMF_MODEL_DIR})

file(GLOB LMF_MODEL_SRC_FILES
    ${LMF_MODEL_DIR}/*.cpp
    ${COMMON_MODEL_DIR}/*.cpp
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${LMF_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${LMF_MODEL_SRC_FILES}
            )
endif()
