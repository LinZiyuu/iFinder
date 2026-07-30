# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/nrf_app)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

set(CN_UTILS_SRC STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/api_conversions.cpp
    )

add_library(CN_UTILS ${CN_UTILS_SRC})


