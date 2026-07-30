#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import os
import re
import sys
import time
import common.python.cls_cmd as cls_cmd

def main() -> None:
    args = _parse_args()
    status = generic_deployment(args.tag)
    sys.exit(status)

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Sanity Check')

    parser.add_argument(
        '--tag', '-t',
        action='store',
        required=True,
        help='Image Tag in image-name:image tag format',
    )
    return parser.parse_args()

def generic_deployment(tag):
    # First detect which docker/podman command to use
    cli = ''
    myCmds = cls_cmd.LocalCmd()
    cmd = 'which podman || true'
    podman_check = myCmds.run(cmd, silent=True)
    if re.search('podman', podman_check.stdout):
        cli = 'sudo podman'
    if cli == '':
        cmd = 'which docker || true'
        docker_check = myCmds.run(cmd, silent=True)
        if re.search('docker', docker_check.stdout):
            cli = 'docker'
    if cli == '':
        print ('No docker / podman installed: quitting')
        return -1

    status = 0
    if cli == 'docker':
        cmd = f'sed -i -e "s@oaisoftwarealliance/oai-lmf:develop@{tag}@" ci-scripts/docker-compose/sanity-check/docker-compose.yaml'
        myCmds.run(cmd)
        cmd = 'cd ci-scripts/docker-compose/sanity-check && docker-compose up -d oai-nrf'
        upStatus = myCmds.run(cmd)
        for line in upStatus.stdout.split('\n'):
            print(line)
        time.sleep(5)
        cmd = 'sudo rm -f /tmp/sanity-lmf-ubuntu.*'
        cmd = 'nohup sudo tshark -i sanity-oai -f "sctp or port 80 or port 8080 or port 8805 or icmp or port 3306" -w /tmp/sanity-lmf-ubuntu.pcap > /tmp/sanity-lmf-ubuntu.log 2>&1 &'
        myCmds.run(cmd)
        time.sleep(5)
        cmd = 'cd ci-scripts/docker-compose/sanity-check && docker-compose up -d'
        upStatus = myCmds.run(cmd)
        for line in upStatus.stdout.split('\n'):
            print(line)
        time.sleep(20)
        cmd = 'docker logs cicd-oai-lmf 2>&1 | grep REGISTERED'
        registerCheck = myCmds.run(cmd)
        if registerCheck.returncode != 0:
            status = -1
        cmd = 'docker inspect --format="STATUS: {{.State.Health.Status}}" cicd-oai-lmf'
        healthStatus = myCmds.run(cmd)
        for line in healthStatus.stdout.split('\n'):
            print(line)
            if re.search('STATUS:', line):
                if re.search('STATUS: healthy', line):
                    status = 0
                else:
                    status = -1
        cmd = 'cd ci-scripts/docker-compose/sanity-check && docker-compose stop -t 30'
        stopStatus = myCmds.run(cmd)
        for line in stopStatus.stdout.split('\n'):
            print(line)
        time.sleep(5)
        cmd = 'mkdir -p archives/sanity-check-ubuntu'
        myCmds.run(cmd)
        cmd = 'docker logs cicd-oai-nrf > archives/sanity-check-ubuntu/oai-nrf.log 2>&1'
        myCmds.run(cmd)
        cmd = 'docker logs cicd-oai-lmf > archives/sanity-check-ubuntu/oai-lmf.log 2>&1'
        myCmds.run(cmd)
        cmd = 'sudo chmod 666 /tmp/sanity-lmf-ubuntu.* && cp /tmp/sanity-lmf-ubuntu.* archives/sanity-check-ubuntu'
        myCmds.run(cmd)
        cmd = 'cd ci-scripts/docker-compose/sanity-check && docker-compose down -v'
        downStatus = myCmds.run(cmd)
        for line in downStatus.stdout.split('\n'):
            print(line)
        cmd = 'docker volume prune --force || true'
        myCmds.run(cmd)
    else:
        # First trying to find the latest develop- image
        cmd = 'sudo podman images | grep nrf'
        nrfImageTagList = myCmds.run(cmd)
        foundLastImage = False
        nrfTagToUse = ''
        for line in nrfImageTagList.stdout.split('\n'):
            if re.search('develop-', line) is not None and not foundLastImage:
                foundLastImage = True
                res = re.search('^.*oai-nrf *(?P<tag>develop-[a-z0-9]+) *', line)
                if res is not None:
                    nrfTagToUse = res.group('tag')
        if nrfTagToUse == '':
            print('could not find a nrf image')
            nrfTagToUse = 'v2.0.1'

        cmd = 'sudo podman network create --subnet 192.168.28.192/26 --ip-range 192.168.28.192/26 cicd-oai-public-net'
        netUpStatus = myCmds.run(cmd)
        for line in netUpStatus.stdout.split('\n'):
            print(line)
        time.sleep(1)
        cwd = os.getcwd()

        cmd = 'sudo podman run --name cicd-oai-nrf --network cicd-oai-public-net --ip 192.168.28.194'
        cmd += f' --env-file ./ci-scripts/podman/nrf.env -d oai-nrf:{nrfTagToUse}'
        contUpStatus = myCmds.run(cmd)
        for line in contUpStatus.stdout.split('\n'):
            print(line)
        time.sleep(20)
        cmd = 'sudo podman inspect --format="NRF STATUS: {{.State.Healthcheck.Status}}" cicd-oai-nrf'
        healthStatus = myCmds.run(cmd)
        for line in healthStatus.stdout.split('\n'):
            print(line)
            if re.search('STATUS:', line):
                if re.search('STATUS: healthy', line):
                    status = 0
                else:
                    status = -1
        cmd = 'sudo podman run --name cicd-oai-lmf --network cicd-oai-public-net --ip 192.168.28.195'
        cmd += f' --env-file ./ci-scripts/podman/lmf.env -d {tag}'
        contUpStatus = myCmds.run(cmd, silent=True)
        for line in contUpStatus.stdout.split('\n'):
            print(line)

        time.sleep(20)

        cmd = 'sudo podman logs cicd-oai-lmf 2>&1 | grep REGISTERED'
        registerCheck = myCmds.run(cmd)
        if registerCheck.returncode != 0:
            status = -1

        cmd = 'sudo podman inspect --format="LMF STATUS: {{.State.Healthcheck.Status}}" cicd-oai-lmf'
        healthStatus = myCmds.run(cmd)
        for line in healthStatus.stdout.split('\n'):
            print(line)
            if re.search('STATUS:', line):
                if re.search('STATUS: healthy', line):
                    status = 0
                else:
                    status = -1

        cmd = 'sudo podman stop -t 2 cicd-oai-nrf cicd-oai-lmf'
        myCmds.run(cmd)
        time.sleep(2)
        cmd = 'mkdir -p archives/sanity-check-rhel'
        myCmds.run(cmd)
        cmd = 'sudo podman logs cicd-oai-nrf > archives/sanity-check-rhel/oai-nrf.log 2>&1'
        myCmds.run(cmd)
        cmd = 'sudo podman logs cicd-oai-lmf > archives/sanity-check-rhel/oai-lmf.log 2>&1'
        myCmds.run(cmd)

        cmd = 'sudo podman rm -f cicd-oai-nrf cicd-oai-lmf'
        contDwnStatus = myCmds.run(cmd)
        for line in contDwnStatus.stdout.split('\n'):
            print(line)
        cmd = 'sudo podman network rm cicd-oai-public-net'
        netDwnStatus = myCmds.run(cmd)
        for line in netDwnStatus.stdout.split('\n'):
            print(line)
        cmd = 'sudo podman volume prune --force || true'
        myCmds.run(cmd)

    return status

if __name__ == '__main__':
    main()
