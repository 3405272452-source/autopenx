FROM ubuntu:22.04

LABEL maintainer="AutoPenX CTF Sandbox"
LABEL description="CTF Pwn challenge sandbox with binary exploitation tools"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and binary exploitation tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    g++ \
    make \
    gdb \
    gdbserver \
    binutils \
    file \
    ltrace \
    strace \
    nasm \
    git \
    curl \
    wget \
    netcat-openbsd \
    socat \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install pwntools and related Python packages
RUN pip3 install --no-cache-dir \
    pwntools==4.12.0 \
    ROPgadget==7.3 \
    one_gadget \
    ropper==1.13.8

# Install pwndbg (GDB plugin for exploit development)
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg \
    && ./setup.sh \
    || echo "pwndbg installation failed, continuing without it"

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash ctfuser

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER ctfuser

CMD ["/bin/bash"]
