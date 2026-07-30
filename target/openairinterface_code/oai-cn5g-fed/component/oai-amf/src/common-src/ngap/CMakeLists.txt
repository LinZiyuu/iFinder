################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
set(NGAP_DIR "${SRC_TOP_DIR}/ngap")
enable_testing()
include(GoogleTest)

include_directories(${3GPP_DIR})
include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${MODEL_DIR})
include_directories(${NGAP_DIR}/libngap)
include_directories(${NGAP_DIR}/libngap_ies)
include_directories(${NGAP_DIR}/ngap_ies)
include_directories(${NGAP_DIR}/ngap_msgs)
include_directories(${NGAP_DIR}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

file(GLOB NGAP_src_files
    ${NGAP_DIR}/libngap/*.c
    ${NGAP_DIR}/libngap_ies/*.c
    ${NGAP_DIR}/ngap_ies/*.cpp
    ${NGAP_DIR}/ngap_msgs/*.cpp
    ${NGAP_DIR}/utils/*.cpp
)

add_library(NGAP STATIC ${NGAP_src_files})

target_link_libraries( NGAP -Wl,--start-group LOGGER COMMON -lfmt -lspdlog -Wl,--end-group )

