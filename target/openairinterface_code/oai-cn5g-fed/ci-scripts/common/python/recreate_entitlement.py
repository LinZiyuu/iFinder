#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import logging
import re
import sys
import cls_cmd

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)8s: %(message)s"
)

import argparse
import re

def recreate_entitlements(args):
    namespace = args.namespace
    myCmds = cls_cmd.LocalCmd()
    try:
       ret = myCmds.run(f'oc get project {namespace}')
       if ret.returncode != 0:
          return 1
       myCmds.run(f'oc delete secret etc-pki-entitlement -n {namespace}')
       myCmds.run(f"oc get secret etc-pki-entitlement -n openshift-config-managed -o json |   jq 'del(.metadata.resourceVersion)' | jq 'del(.metadata.creationTimestamp)' |   jq 'del(.metadata.uid)' | jq 'del(.metadata.namespace)' |   oc create -n {namespace} -f -")
       exitcode = 0
    except Exception as e:
       print(f"Exception with reason {e}, in re-creating entitlements in namespace {namespace}")
       exitcode = 1
    myCmds.close()
    return exitcode

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-n', '--namespace', default='oaicicd-core', help="Kubernetes namespace name")
        parser.set_defaults(func=recreate_entitlements)
        args = parser.parse_args()
        rc = args.func(args)
        print("Execution finished, exiting with code {}".format(str(rc)))
        sys.exit(rc)
    except Exception as e:
        print("main() caught exception %s" %(str(e)))
        sys.exit(1)

if __name__ == "__main__":
    main()
