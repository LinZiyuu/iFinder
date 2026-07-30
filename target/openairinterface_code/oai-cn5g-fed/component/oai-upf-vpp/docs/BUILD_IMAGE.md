# 1.  Retrieve the proper code version #

```bash
$ git clone https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf-vpp.git

$ cd oai-cn5g-upf-vpp

$ git checkout develop
```

# 2. Generic Parameters #

Here in our network configuration, we need to pass the "GIT PROXY" configuration.

*   If you do not need, remove the `--build-arg NEEDED_GIT_PROXY=".."` option.
*   If you do need it, change with your proxy value.

# 3. Build vpp-upf image #
## 3.1 On a Ubuntu 18.04 Host ##

```bash
$ docker build --target oai-upf-vpp --tag oai-upf-vpp:latest \
               --file docker/Dockerfile.upf-vpp.ubuntu \
               .
```

## 3.2 On a Ubuntu 20.04 Host ##

```bash
$ docker build --target oai-upf-vpp --tag oai-upf-vpp:latest \
               --file docker/Dockerfile.upf-vpp.ubuntu \
               --build-arg BASE_IMAGE=ubuntu:focal .
```

## 3.3 On a Ubuntu 22.04 Host ##

```bash
$ docker build --target oai-upf-vpp --tag oai-upf-vpp:latest \
               --file docker/Dockerfile.upf-vpp.ubuntu \
               --build-arg BASE_IMAGE=ubuntu:jammy .
```

##  3.4 On a RHEL 7 Host ##

```bash
$ docker build --target oai-upf-vpp --tag oai-upf-vpp:latest \
               --file docker/Dockerfile.upf-vpp.rhel7 \
               .
```
