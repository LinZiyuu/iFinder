#!/bin/bash
# SPDX-License-Identifier: MIT

set -eo pipefail

STATUS=0
LMF_PORT_FOR_N11_HTTP=80
LMF_IP_N11_INTERFACE=$(ifconfig $SBI_IF_NAME | grep inet | awk {'print $2'})
N11_PORT_STATUS=$(netstat -tnpl | grep -o "$LMF_IP_N11_INTERFACE:$LMF_PORT_FOR_N11_HTTP")

if [[ -z $N11_PORT_STATUS ]]; then
    STATUS=1
    echo "Healthcheck error: N11/SBI TCP/HTTP port $LMF_PORT_FOR_N11_HTTP is not listening"
fi

exit $STATUS

