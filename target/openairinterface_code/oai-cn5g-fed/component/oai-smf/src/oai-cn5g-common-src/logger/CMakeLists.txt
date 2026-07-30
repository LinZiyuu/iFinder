################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
cmake_minimum_required (VERSION 3.22.1)
project( LOGGER )
set( LIBLOGGER_SOURCES         
        ${LOGGER_DIR}/nf-tp.cpp
        ${LOGGER_DIR}/lttng_logger_base.cpp
        ${LOGGER_DIR}/spd_logger_base.cpp
        ${LOGGER_DIR}/logger_base.cpp
)
add_library( LOGGER STATIC ${LIBLOGGER_SOURCES} )
target_link_libraries( LOGGER -Wl,--start-group -lfmt -lspdlog -Wl,--end-group )
