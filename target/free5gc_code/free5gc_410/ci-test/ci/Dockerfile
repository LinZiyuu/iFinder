FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=$PATH:/usr/local/go/bin
ENV PACKETRUSHER=/root/PacketRusher

# Install essential packages and dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    linux-headers-generic \
    make \
    git \
    wget \
    tar \
    kmod \
    curl \
    jq \
    iputils-ping \
    net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go 1.24.5
RUN rm -rf /usr/local/go && \
    wget https://go.dev/dl/go1.24.5.linux-amd64.tar.gz -O - | tar -C /usr/local -zxvf - && \
    echo "export PATH=$PATH:/usr/local/go/bin" >> /root/.profile

# Clone PacketRusher and build binary only
RUN git clone https://github.com/HewlettPackard/PacketRusher ${PACKETRUSHER} && \
    # Build PacketRusher binary
    cd ${PACKETRUSHER} && \
    go mod download && \
    go build cmd/packetrusher.go

# Copy gtp5g source to a specific location
RUN cp -r ${PACKETRUSHER}/lib/gtp5g /usr/local/src/gtp5g

# Add build script for gtp5g
COPY <<'EOF' /usr/local/bin/build-gtp5g.sh
#!/bin/bash
cd /usr/local/src/gtp5g
make clean
make
make install
depmod -a
EOF

RUN chmod +x /usr/local/bin/build-gtp5g.sh

# Set working directory
WORKDIR /root

# Set volume for persistent data
VOLUME [ "/root" ]

# Default command
CMD ["/bin/bash"]
