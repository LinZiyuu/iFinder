#!/usr/bin/env bash

#"""
#/*
# * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# * contributor license agreements.  See the NOTICE file distributed with
# * this work for additional information regarding copyright ownership.
# * The OpenAirInterface Software Alliance licenses this file to You under
# * the OAI Public License, Version 1.1  (the "License"); you may not use this
# * file except in compliance with the License. You may obtain a copy of the
# * License at
# *
# *      http://www.openairinterface.org/?page_id=698
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *-------------------------------------------------------------------------------
# * For more information about the OpenAirInterface (OAI) Software Alliance:
# *      contact@openairinterface.org
# */
#
#/*! \file entrypoint.sh
#   \author  Rohan KHARADE
#   \date 2021
#   \email: rohan.kharade@openairinterface.org
#*/
#"""

# files are common to docker and native installation
#____________
# init.conf          => upf config
# startup_debug.conf => vpp config (To Do -> sed location of init.conf file)
# profile.json       => NRF profile
# run_sh             => run vpp
# The init.conf and profile.json files are generated  using the create_configuration.py Python script
# The startup_debug.conf file contains placeholders (@VALUE@) which will be overwritten
#____________

set -euo pipefail

export CONFIG_DIR="/openair-upf/etc"
BIN_DIR="/openair-upf/bin"

REGISTER_NRF=${REGISTER_NRF:-no}
NRF_IPV4_ADDRESS=${NRF_IPV4_ADDRESS:-0.0.0.0}
NRF_PORT=${NRF_PORT:-80}
NRF_API_VERSION=${NRF_API_VERSION:-v1}
NRF_FQDN=${NRF_FQDN:-oai-nrf}
USE_FQDN_DNS=${USE_FQDN_DNS:-no}

if [[ ${USE_FQDN_DNS} == "yes" ]];then
    NRF_IPV4_ADDRESS=(`getent hosts $NRF_FQDN | awk '{print $1}'`)
    echo -e "\nResolving NRF by FQDN : $NRF_FQDN - $NRF_IPV4_ADDRESS"
fi

export UUID=$(cat /proc/sys/kernel/random/uuid)

###############################
# UPF Config
###############################

python3 $CONFIG_DIR/create_configuration.py $CONFIG_DIR/init.conf $CONFIG_DIR/upf_profile.json $CONFIG_DIR/startup_debug.conf --rename

if [[ $? -ne 0 ]]; then
    echo "Error in creating configuration files"
    exit 1
fi

exec "$@"