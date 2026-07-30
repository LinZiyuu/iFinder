# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(NRF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

include_directories(${NRF_API_SERVER_DIR}/api)
include_directories(${NRF_API_SERVER_DIR}/impl)
include_directories(${NRF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/nrf_app)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

file(GLOB NRF_API_SERVER_src_files
    ${NRF_API_SERVER_DIR}/nrf-api-server.cpp
    ${NRF_API_SERVER_DIR}/nrf-http2-server.cpp
    ${NRF_API_SERVER_DIR}/api/*.cpp
    ${NRF_API_SERVER_DIR}/impl/*.cpp
)
 
add_library(NRF_API STATIC
           ${NRF_API_SERVER_src_files})
