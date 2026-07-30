################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
cmake_minimum_required (VERSION 3.22.1)
project(UNIT_TESTING_COMMON_SRC)

enable_testing()
include(GoogleTest)

# Override options for COMMON
set (  PACKAGE_NAME                    "COMMON" )

set (NAS_TEST_DIR   ${NAS_DIR}/test)
set (NGAP_TEST_DIR  ${NGAP_DIR}/test)

include_directories(${3GPP_DIR})
include_directories(${COMMON_DIR})
include_directories(${LOGGER_DIR})
include_directories(${CONFIG_DIR})
include_directories(${MODEL_DIR}/common_model)
include_directories(${NAS_DIR}/5gmm-msgs)
include_directories(${NAS_DIR}/common)
include_directories(${NAS_DIR}/ies)
include_directories(${NAS_DIR}/utils)
include_directories(${NGAP_DIR}/libngap)
include_directories(${NGAP_DIR}/libngap_ies)
include_directories(${NGAP_DIR}/ngap_ies)
include_directories(${NGAP_DIR}/ngap_msgs)
include_directories(${NGAP_DIR}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)

add_executable(unit_tests 
  main.cpp
  ${NAS_TEST_DIR}/test_msg.cpp
  ${NGAP_TEST_DIR}/test_msg.cpp) 

target_link_libraries(unit_tests 
 -Wl,--start-group COMMON  NAS NGAP LOGGER UTILS -lboost_system 
 -lboost_thread -lboost_date_time -lfmt -lspdlog -lssl -Wl,--end-group
   gtest pthread m rt boost_system)

gtest_discover_tests(unit_tests)
