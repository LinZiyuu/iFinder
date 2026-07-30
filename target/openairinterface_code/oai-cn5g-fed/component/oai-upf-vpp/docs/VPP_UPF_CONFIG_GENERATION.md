# VPP UPF Configuration Generation

The VPP-UPF configuration for different UPF deployment options (A-UPF, I-UPF, ULCL) are not compatible with each other.
The example described in [VPP_UPF_CONFIG](./VPP_UPF_CONFIG.md) shows a central UPF node with one N3 and one N6
interface.

To ease the deployment, the UPF configuration can be auto-generated using the `create_configuration.py` script. It is
located in `scripts/upf_conf/create_configuration.py`. If you choose to use the official OAI docker images (from v1.5.0), this script is
executed upon start of the containers. 

It takes three positional arguments:

```
usage: create_configuration.py
       [-h]
       [--rename]
       init_path
       profile_path
       startup_path
```

The `init_path` is the path to the init file that will be generated. A json file is written to the `profile_path` which
contains the UPF profile which is sent to the NRF.

The `startup_path` requires an existing VPP `startup_debug.conf` file with placeholders (`@value@`). These will be
overwritten with the corresponding environment variables.

If you choose to rename using the `--rename` option, the host interfaces are renamed from e.g. `eth1` to `n6-3`.
Which interface is renamed depends on the configured subnet.

## Environment variables

The UPF configuration is built entirely from environment variables. There are static variables, which always have to be
present:

| Environment Variable | Description                                      | Used in                   |
|----------------------|--------------------------------------------------|---------------------------|
| NAME                 | Used to build the UPF FQDN                       | init.conf, profile.json   |
| MNC                  | Used to build the UPF FQDN                       | init.conf, profile.json   |
| MCC                  | Used to build the UPF FQDN                       | init.conf, profile.json   |
| REALM                | Used to build the UPF FQDN                       | init.conf, profile.json   |
| VPP_MAIN_CORE        | Which CPU core ID to use for the main thread     | startup_debug.conf        |
| VPP_CORE_WORKER      | Which CPU core ID to use for the worker thread * | startup_debug.conf        |
| SNSSAI_SD            | SD from the SNSSAI                               | profile.json              |
| SNSSAI_SST           | SST from the SNSSAI                              | profile.json              |
| DNN                  | DNN                                              | profile.json              |
| VPP_PLUGIN_PATH      | Path where the UPG VPP plugin is installed       | startup_debug.conf        |

&ast; This config from VPP allows to configure more than one worker thread, e.g. 1-4, but it is not recommended in the
VPP-UPF, as there are race conditions.

The UPF FQDN is built as follows:
```
<name>.node.5gcn.mnc<mnc>.mcc<mcc>.<realm>
```
The NAME variable is translated to lower-case.   


Then, there are support features which you also have to configure:

| Environment Variable | Description                       |
|----------------------|-----------------------------------|
| REGISTER_NRF         | If the UPF should register to NRF |
| NRF_IP_ADDR          | The NRF IP address                |
| NRF_PORT             | The NRF Port                      |
| HTTP_VERSION         | HTTP version towards NRF (1/2)    |

Apart from this global configuration, you can dynamically configure your interfaces. 
The syntax to configure an interface is as follows:
```
IF_<Index>_<Value>
```

Each interface can have multiple values, whereas the index describes the interface.
The following values are available:

| Value     | Description                                 | Mandatory        |
|-----------|---------------------------------------------|------------------|
| IP        | IP address of the interface**               | yes              |
| TYPE      | Either N3, N4, N6 or N9                     | yes              |
| NWI       | Network Instance of the interface           | yes (not for N4) |
| DNAI      | Data Network Access Identifier              | no               |
| IP_REMOTE | Next hop IP, optional when using `--rename` | yes/no           |

&ast;&ast; Should belong to subnet of existing host interface

An example of a UPF configuration is as follows (see also the docker-compose file):
```
- IF_1_IP=192.168.70.201
- IF_1_TYPE=N4
- IF_2_IP=192.168.72.201
- IF_2_TYPE=N3
- IF_2_NWI=access.oai.org
- IF_3_IP=192.168.73.201
- IF_3_TYPE=N6
- IF_3_IP_REMOTE=192.168.73.135 # EXT-DN IP Address
- IF_3_NWI=internet.oai.org
- NAME=VPP-UPF
- MNC=95
- MCC=208
- REALM=3gppnetwork.org
- VPP_MAIN_CORE=0
- VPP_CORE_WORKER=1
- VPP_PLUGIN_PATH=/usr/lib/x86_64-linux-gnu/vpp_plugins/ # Ubntu18.04
- SNSSAI_SD=123
- SNSSAI_SST=222
- DNN=default
- REGISTER_NRF=yes
- NRF_IP_ADDR=192.168.70.130
- NRF_PORT=80
- HTTP_VERSION=1
```


## Interfaces
We use veth pairs to configure the UPF interfaces. Each UPF interface (e.g. N3) has a host interface IP and the IP address
used for signaling. You need one subnet for each UPF interface. In a typical deployment, you need at least three subnets:
* Signaling (N4)
* Access (N3)
* Core/Internet (N6). 

The `IP` value should belong to the same subnet as the host interface, but must not be the same. 

The `IP_REMOTE` value also needs to be in the same subnet and is used to setup the routes accordingly. 
When you use the `--rename` option, the `IP_REMOTE` is automatically calculated from the subnet from the `IP` value.
The remote IP is always the first host in the subnet, e.g. for the IP `192.168.70.201` in the subnet `192.168.70.0/24`, 
the remote IP is `192.168.70.1`.

The value you provide overrides the default value. When you do not rename the interfaces, you need to manually specify
the remote IP address.


## Interface Configuration Examples

The dynamic creation allows you to configure different UPF types.

### Central UPF 
This UPF has one N3, one N4 and one N6 interface:

```
- IF_1_IP=192.168.70.201
- IF_1_TYPE=N4
- IF_2_IP=192.168.72.201
- IF_2_TYPE=N3
- IF_2_NWI=access.oai.org
- IF_3_IP=192.168.73.201
- IF_3_TYPE=N6
- IF_3_NWI=internet.oai.org
```

### A-UPF 
This UPF has one N9, one N4 and one N6 interface:
```
- IF_1_IP=192.168.70.202
- IF_1_TYPE=N4
- IF_2_IP=192.168.74.202
- IF_2_TYPE=N9
- IF_2_NWI=iupf.node.5gcn.mnc98.mcc208.3gppnetwork.org
- IF_2_DNAI=iupf
- IF_3_IP=192.168.75.202
- IF_3_TYPE=N6
- IF_3_NWI=internet.oai.org
- IF_3_DNAI=internet
```

When you want to use multiple UPFs which should be chained or form a graph, you need to ensure that the `NWI` of the 
configuration matches the `FQDN` of the other UPF. In this case, `IUPF` should have the following FQDN config:
```
- NAME=IUPF
- MNC=98
- MCC=208
- REALM=3gppnetwork.org
```

### I-UPF
This UPF has one N3, one N4 and one N9 interface:
```
- IF_1_IP=192.168.70.203
- IF_1_TYPE=N4
- IF_2_IP=192.168.72.203
- IF_2_TYPE=N3
- IF_2_NWI=access.oai.org
- IF_2_DNAI=access
- IF_3_IP=192.168.74.203
- IF_3_TYPE=N9
- IF_3_NWI=aupf.node.5gcn.mnc98.mcc208.3gppnetwork.org
- IF_3_DNAI=aupf
```

As you can see, the N9 interface is in the same subnet as the N9 interface of the I-UPF example. This means
that the SMF will create an edge between these two nodes (as long as the FQDN/NWI configuration matches).
Also, the DNAI is configured for these examples to enable SMF in selecting a specific UPF for a PDU session.

### UL CL
This UPF has one N3, one N4 and two N9 interfaces:

```
- IF_1_IP=192.168.70.204
- IF_1_TYPE=N4
- IF_2_IP=192.168.72.204
- IF_2_TYPE=N3
- IF_2_NWI=access.oai.org
- IF_2_DNAI=access
- IF_3_IP=192.168.74.204
- IF_3_TYPE=N9
- IF_3_NWI=aupf1.node.5gcn.mnc98.mcc208.3gppnetwork.org
- IF_3_DNAI=aupf1
- IF_4_IP=192.168.76.204
- IF_3_TYPE=N9
- IF_3_NWI=aupf2.node.5gcn.mnc98.mcc208.3gppnetwork.org
- IF_4_DNAI=aupf2
```
