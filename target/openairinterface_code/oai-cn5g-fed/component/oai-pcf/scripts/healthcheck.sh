#!/bin/bash
# SPDX-License-Identifier: MIT

set -eo pipefail

STATUS=0
PCF_INTERFACE_NAME_FOR_SBI=$(yq '.nfs.pcf.sbi.interface_name' /openair-pcf/etc/config.yaml)
PCF_INTERFACE_PORT_FOR_SBI=$(yq '.nfs.pcf.sbi.port' /openair-pcf/etc/config.yaml)

PCF_IP_SBI_INTERFACE=$(ifconfig $PCF_INTERFACE_NAME_FOR_SBI | grep inet | grep -v inet6 | awk {'print $2'})
#Check if entrypoint properly configured the conf file and no parameter is unset(optional)
PCF_SBI_PORT_STATUS=$(netstat -tnpl | grep -o "$PCF_IP_SBI_INTERFACE:$PCF_INTERFACE_PORT_FOR_SBI")

if [[ -z $PCF_SBI_PORT_STATUS ]]; then
	STATUS=-1
	echo "Healthcheck error: UNHEALTHY SBI TCP/HTTP port $PCF_INTERFACE_PORT_FOR_SBI is not listening."
fi

exit $STATUS
