
##### Tools used 
* UPF ([VPP-UPF](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp))
* PFCP Simulator ([pfcp-kitchen-sink](https://github.com/infinitydon/pfcp-kitchen-sink))
* Traffic generator ([Scapy](https://github.com/secdev/scapy.git))


                                     ------------------------
                                     |    PFCP Simulator    |
                                     ------------------------
                                                |
                                                | N4
        --------------------       N3     -------------
        |                  |   ---------> |           |
        | Traffic Generaor |              |    UPF    |
        |                  |   <--------- |           |
        --------------------        N6    -------------
### Step 1: Setup UPF
We are using [bare metal setup of VPP-UPF](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp/-/blob/develop/docs/INSTALL_ON_HOST.md) here, since the objective of bracket test here is to create developer/debug environment. <br/>
* Create Network for N3, N4 and N6 <br/>
```bash
# Create docker bridges
docker network create --driver=bridge --subnet=192.168.72.0/24 -o "com.docker.network.bridge.name"="cn5g-access" oai-public-access
docker network create --driver=bridge --subnet=192.168.73.0/24 -o "com.docker.network.bridge.name"="cn5g-core" oai-public-core
docker network create --driver=bridge --subnet=192.168.70.0/24 -o "com.docker.network.bridge.name"="demo-oai" demo-oai-public-net

# Create Veth Pairs for interfaces N3, N4, N6 and add it to the docker network
sudo ip link add name n4in type veth peer name n4out
sudo brctl addif demo-oai n4out
sudo ip link set dev n4out up

sudo ip link add name n6in type veth peer name n6out
sudo brctl addif demo-oai n6out
sudo ip link set dev n6out up

sudo ip link add name n3in type veth peer name n3out
sudo brctl addif demo-oai n3out
sudo ip link set dev n3out up
```
* Run VPP_UPF  <br/>
Make sure you have copied [startup_host.conf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp/-/blob/develop/scripts/startup_host.conf) and [init_host.conf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp/-/blob/develop/scripts/init_host.conf) to vpp folder and updated config paths accordingly.

```bash
cd vpp/
sudo ./build-root/build-vpp-native/vpp/bin/vpp -c startup_host.conf
```
### Step 2: Create PFCP session
Follow instruction [illustrated here](https://github.com/infinitydon/pfcp-kitchen-sink#pfcp-kitchen-sink) to build PFCP simulator. <br/>
Create PFCP session using sample [session.yaml](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp/-/blob/develop/scripts/session.yaml). This will create PFCP session of single UE flow for uplink and downlink direction. <br/>
```bash
pfcp-kitchen-sink$ ./pfcpclient -r 192.168.70.201:8805 -s session.yaml
PFCP client v0.1
2 sessions created successfully
```
### Step 3: Traffic Test
* Get scapy
```bash
$ git clone https://github.com/secdev/scapy.git
```
* Send DL packet
```bash
$ cd scapy/ && sudo ./run_scapy
>> sendp(Ether(dst="00:00:00:00:00:0b")/
                    IP(src="192.168.73.1",dst="10.10.10.10",version=4)/
                    ICMP(), iface="n6out", count=10)
```
* Send UL packet
```bash
$ cd scapy/ && sudo ./run_scapy
>>> from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
>>> sendp(Ether(dst="00:00:00:00:00:0a")/
                    IP(src="192.168.72.1",dst="192.168.72.201")/
                    UDP(dport=2152)/GTP_U_Header(teid=1234)/ GTPPDUSessionContainer(type=1, QFI=5)/ 
                    IP(src="10.10.10.10",dst="192.168.73.1",version=4)/ 
                    ICMP(), iface="n3out", count=10)
```
