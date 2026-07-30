# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(NEF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

include_directories(${NEF_API_SERVER_DIR}/api)
include_directories(${NEF_API_SERVER_DIR}/impl)
include_directories(${NEF_API_SERVER_DIR}/model)
include_directories(${NEF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/nef_app)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)

file(GLOB NEF_API_SERVER_src_files
    ${NEF_API_SERVER_DIR}/nef-api-server.cpp
    ${NEF_API_SERVER_DIR}/nef-http2-server.cpp
    ${NEF_API_SERVER_DIR}/model/*.cpp
    ${NEF_API_SERVER_DIR}/api/*.cpp
    ${NEF_API_SERVER_DIR}/impl/*.cpp
)

add_library(NEF_API STATIC
           ${NEF_API_SERVER_src_files})
