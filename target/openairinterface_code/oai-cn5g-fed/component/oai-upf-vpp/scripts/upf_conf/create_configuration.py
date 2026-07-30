import argparse
import ipaddress
import os
import sys
import json
import subprocess
import re

import textwrap

CAPACITY = 100
HEARTBEAT_TIMER = 10
PRIORITY = 1
VPP_UPF_RELEASE = "16"


class InitFile:

    def __init__(self, upf_conf):
        self.upf_conf = upf_conf
        self.last_table_id = 0
        self.ip_tables = []
        self.interfaces = []
        self.gtp_endpoints = []
        self.ip_routes = []
        self.nwis = []
        self.pfcp_endpoints = []
        self.node_id = ""
        self.release = ""

    def create_upf_init_iface(self, iface):
        if not iface.get("ip"):
            print(
                f"Configuration error. Please specify IP for {iface['name'].upper()} interface")
            exit(-1)

        self.interfaces.append(textwrap.dedent(f"""\
            create host-interface name {iface["name"]}
            set interface mtu 1500 host-{iface["name"]}
            set interface ip table host-{iface["name"]} {iface["table_id"]}
            set interface ip address host-{iface["name"]} {iface["ip"]}/24
            set interface state host-{iface["name"]} up
            """))

    def create_ip_route(self, iface):
        if not iface.get("ip_remote"):
            print(
                f"You need to specify IP remote manually for interface {iface['name']} if you do not rename the interfaces")
            exit(-1)

        self.ip_routes.append(
            f"ip route add 0.0.0.0/0 table {iface['table_id']} via {iface['ip_remote']} host-{iface['name']}\n")

    def create_upf_nwi(self, iface):
        if not iface.get('nwi'):
            print(f"You need to specify NWI for interface {iface['name']}")
            exit(-1)
        self.nwis.append(
            f"upf nwi name {iface['nwi']} vrf {iface['table_id']}\n")

    def create_gtp_endpoint(self, iface):
        self.gtp_endpoints.append(
            f"upf gtpu endpoint ip {iface['ip']} nwi {iface['nwi']} teid 0x000004d2/{iface['table_id']}\n")

    def create_pfcp_endpoint(self, iface):
        self.pfcp_endpoints.append(
            f"upf pfcp endpoint ip {iface['ip']} vrf {iface['table_id']}\n")

    def create_ip_table(self, iface):
        self.ip_tables.append(
            f"ip table add {iface['table_id']}\n")

    def create_node_id(self):
        self.node_id = f"upf node-id fqdn {self.upf_conf['fqdn']}\n"

    def create_upf_specification(self):
        self.release = f"upf specification release {VPP_UPF_RELEASE}\n"

    def to_config_string(self):
        conf = ""
        for ip_table in self.ip_tables:
            conf += ip_table
        conf += "\n"
        for interface in self.interfaces:
            conf += interface
            conf += "\n"
        for route in self.ip_routes:
            conf += route
        conf += "\n"
        for pfcp in self.pfcp_endpoints:
            conf += pfcp
        conf += "\n"
        conf += self.node_id
        conf += "\n"
        for nwi in self.nwis:
            conf += nwi
        conf += "\n"
        conf += self.release
        conf += "\n"
        for gtp in self.gtp_endpoints:
            conf += gtp
        conf += "\n"

        return conf

    def create_init_conf(self):
        for idx in self.upf_conf["ifaces"]:
            iface = self.upf_conf["ifaces"][idx]
            if iface["type"] == "N4":
                iface["table_id"] = "0"
                self.create_pfcp_endpoint(iface)
            else:
                self.last_table_id += 1
                iface["table_id"] = str(self.last_table_id)
                self.create_ip_table(iface)
                self.create_upf_nwi(iface)

            if iface["type"] == "N3" or iface["type"] == "N9":
                self.create_gtp_endpoint(iface)

            self.create_upf_init_iface(iface)

            self.create_ip_route(iface)

        self.create_upf_specification()
        self.create_node_id()

        return self.to_config_string()


class Profile:
    def __init__(self, upf_conf) -> None:
        self.upf_conf = upf_conf

    def create_upf_profile(self):
        # create the dictionary
        profile = {}
        upf_ifaces = []
        n4_address = ""
        dnais = []
        dnais_nw_instance = {}
        for idx in self.upf_conf["ifaces"]:
            iface = self.upf_conf["ifaces"][idx]
            if iface["type"] == "N4":
                n4_address = iface["ip"]
            else:
                upf_iface = {"endpointFqdn": iface["nwi"], "interfaceType": iface["type"],
                             "ipv4EndpointAddresses": [iface["ip"]], "networkInstance": iface["nwi"]}

                # TODO should we have a distinct value for endpointFQDN?
                upf_ifaces.append(upf_iface)

                if iface.get("dnai"):
                    dnais.append(iface["dnai"])
                    dnais_nw_instance[iface["dnai"]] = iface["nwi"]
                else:
                    print(f"Warning: You did not configure DNAI for interface {iface['name']}. "
                          f"Edge computing not supported.")
        profile["nfInstanceId"] = self.upf_conf["uuid"]
        profile["capacity"] = CAPACITY
        profile["fqdn"] = self.upf_conf["fqdn"]
        profile["heartBeatTimer"] = HEARTBEAT_TIMER
        profile["ipv4Addresses"] = [n4_address]
        profile["json_data"] = None
        profile["nfInstanceName"] = self.upf_conf['name']
        profile["nfServices"] = []
        profile["nfStatus"] = "REGISTERED"
        profile["nfType"] = "UPF"
        profile["priority"] = PRIORITY
        snssai = {"sd": f"{self.upf_conf['snssai_sd']}", "sst": int(self.upf_conf["snssai_sst"])}
        profile["sNssais"] = [snssai]
        profile["upfInfo"] = {}
        snssai_item = {"dnnUpfInfoList": [], "sNssai": snssai}
        dnn = {"dnn": self.upf_conf["dnn"]}
        if len(dnais) > 0:
            dnn["dnaiList"] = dnais
            dnn["dnaiNwInstanceList"] = dnais_nw_instance
        snssai_item["dnnUpfInfoList"].append(dnn)
        profile["upfInfo"]["sNssaiUpfInfoList"] = [snssai_item]
        profile["upfInfo"]["interfaceUpfInfoList"] = upf_ifaces

        return json.dumps(profile, indent=4)


def get_id_value_from_list_env(k_in):
    first_pos = k_in.find("_")
    second_pos = k_in[first_pos + 1:].find("_") + first_pos + 1
    idx = k_in[first_pos + 1:second_pos]
    val = k_in[second_pos + 1:]

    return idx, val


def check_exists(upf_conf, key):
    if not upf_conf.get(key):
        print("Mandatory environment variable " + key.upper() + " is not set.")
        exit(-1)


def read_environment():
    upf_conf = {"ifaces": {}, "dnais": {}}
    for k, v in os.environ.items():
        k = k.lower()
        # IF_ID_VALUE
        if k.startswith("if"):
            (idx, k_new) = get_id_value_from_list_env(k)
            if not upf_conf["ifaces"].get(idx):
                upf_conf["ifaces"][idx] = {}
            upf_conf["ifaces"][idx][k_new] = v
            if k_new == "type":
                upf_conf["ifaces"][idx]["name"] = f"{v.lower()}-{idx}"

        elif k.startswith("dnai"):
            (idx, k_new) = get_id_value_from_list_env(k)
            if not upf_conf["dnais"].get(idx):
                upf_conf["dnais"][idx] = {}
            upf_conf["dnais"][idx][k_new] = v
        else:
            upf_conf[k] = v

    if len(upf_conf["ifaces"]) < 3:
        print("You need at least 3 interfaces: N3, N6/N9 and N4")
        exit(-1)

    for iface_conf in upf_conf["ifaces"].values():
        if not iface_conf.get("ip"):
            print(f"You need to specify IP address for {iface_conf['name']}")
            exit(-1)

    check_exists(upf_conf, "name")
    check_exists(upf_conf, "mnc")
    check_exists(upf_conf, "mcc")
    check_exists(upf_conf, "realm")
    check_exists(upf_conf, "uuid")
    check_exists(upf_conf, "snssai_sd")
    check_exists(upf_conf, "snssai_sst")
    check_exists(upf_conf, "dnn")

    upf_conf[
        "fqdn"] = f"""{upf_conf["name"].lower()}.node.5gcn.mnc{upf_conf["mnc"]}.mcc{upf_conf["mcc"]}.{upf_conf["realm"]}"""
    return upf_conf


def get_interfaces():
    res = subprocess.run(['ip', '-4', '-o', 'addr'], stdout=subprocess.PIPE)

    ifaces = {}
    for line in res.stdout.splitlines():
        line_split = line.decode().split()
        iface_name = line_split[1].strip()
        iface_ip = line_split[3].strip()
        ifaces[iface_name] = iface_ip

    return ifaces


def change_ifname(old, new):
    subprocess.run(["ip", "link", "set", old, "down"])
    subprocess.run(["ip", "link", "set", old, "name", new])
    subprocess.run(["ip", "link", "set", new, "up"])


def overwrite_vars(upf_conf, path):
    to_write = ""
    with open(path, "r") as f:
        for line in f.readlines():
            match = re.search("@.*@", line)
            if match:
                var_name = match.group()[1:-1]  # remove the @
                check_exists(upf_conf, var_name.lower())
                value = upf_conf[var_name.lower()]
                line = re.sub("@.*@", value, line)
            to_write += line

    with open(path, "w") as f:
        f.write(to_write)


def main():
    parser = argparse.ArgumentParser(description="Create VPP-UPF configuration files for the OAI")
    parser.add_argument('--rename', dest='rename', default=False, action='store_true',
                        help="Rename the host interfaces. When set, automatic remote IP deduction is supported.")
    parser.add_argument('init_path', metavar='init_path', nargs=1, help="Path where the init conf file is written")
    parser.add_argument('profile_path', metavar='profile_path', nargs=1, help="Path where the profile file is written")
    parser.add_argument('startup_path', metavar='startup_path', nargs=1, help="Path to existing startup.conf file")

    args = parser.parse_args()

    print("Generating config file...")
    print("Reading environment variables")

    upf_conf = read_environment()

    overwrite_vars(upf_conf, args.startup_path[0])

    if args.rename:
        print("Renaming Host Interfaces")

        # Now we set the correct network interface
        # We check if the ip belongs to the subnet
        ifaces_host = get_interfaces()
        for iface_conf in upf_conf["ifaces"].values():
            for if_name in ifaces_host:
                ip_host = ifaces_host[if_name]

                if ipaddress.ip_address(iface_conf["ip"]) in ipaddress.ip_network(ip_host, strict=False):
                    change_ifname(if_name, iface_conf["name"])
                    # use first host as IP remote if it does not exist
                    if not iface_conf.get("ip_remote"):
                        hosts = list(ipaddress.ip_network(ip_host, strict=False).hosts())
                        iface_conf["ip_remote"] = str(hosts[0])

    profile = Profile(upf_conf)
    init_conf = InitFile(upf_conf)

    with open(args.init_path[0], "w") as init_file:
        upf_cfg = init_conf.create_init_conf()
        init_file.write(upf_cfg)

    with open(args.profile_path[0], "w") as profile_file:
        upf_profile = profile.create_upf_profile()
        profile_file.write(upf_profile)

    print("Done generating the config files")

    if len(sys.argv) != 4 or sys.argv[3] != "--no-rename":
        return 0

    print("Renaming interfaces...")

    print("Done setting the configuration")
    return 0


if __name__ == "__main__":
    main()
