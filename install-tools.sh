#!/bin/bash
# setup-testing-env.sh

mkdir -p ./test-scripts ./results

cat > ./test-scripts/install-tools.sh << 'EOF'
#!/bin/bash
apt-get update && apt-get install -y \
    nmap \
    netcat-traditional \
    tcpdump \
    strace \
    lsof \
    psmisc \
    procps \
    curl \
    wget \
    git \
    ssh \
    sftp \
    socat \
    jq \
    base64 \
    xxd \
    binutils \
    python3 \
    python3-pip \
    docker.io \
    --no-install-recommends
    
pip3 install requests lxml netaddr
EOF

chmod +x ./test-scripts/install-tools.sh
