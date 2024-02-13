FROM occlum/occlum:0.30.0-ubuntu20.04 as builder

ARG KBC=cc-kbc

ENV OCCLUM_RELEASE_BUILD=1
WORKDIR /occlum_build
RUN git clone https://github.com/Martinits/occlum
WORKDIR /occlum_build/occlum
RUN git checkout 0.30.0
RUN sed -ri 's/^default = \[(.+)\]/default = [\1, "eccfs_root"]/g' src/libos/Cargo.toml
RUN make submodule
RUN source /opt/intel/sgxsdk/environment && make
RUN make install

RUN rustup default stable
COPY src/ /enclave-cc/src/
RUN cd /enclave-cc/src/enclave-agent && \
    . $HOME/.cargo/env && \
    make ${KBC}
RUN cd /enclave-cc/src/runtime-boot/init && \
    . $HOME/.cargo/env && \
    cargo build --release

WORKDIR /run/unified
COPY tools/packaging/build/unified-bundle/enclave-agent-${KBC}.yaml .
COPY tools/packaging/build/unified-bundle/boot_template.yaml .
COPY tools/packaging/build/unified-bundle/init.yaml .
COPY tools/packaging/build/unified-bundle/agent-instance.filter .

ARG SGX_MODE=HW
RUN export PATH="$PATH:/opt/occlum/build/bin" && \
    occlum new occlum_instance && cd occlum_instance && \
    copy_bom -f ../enclave-agent-${KBC}.yaml --root image \
    --include-dir /opt/occlum/etc/template && \
    copy_bom -f ../init.yaml --root initfs \
    --include-dir /opt/occlum/etc/template && \
    mv Occlum.json Occlum.json.orig && \
    jq -a -f ../agent-instance.filter Occlum.json.orig > Occlum.json && \
    SGX_MODE=${SGX_MODE} occlum build && \
    if [ $SGX_MODE="SIM" ]; then \
        export DEBUG="--debug"; \
    fi; occlum package ${DEBUG}

FROM ubuntu:20.04

RUN apt-get update && \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    gnupg

ARG OCCLUM_VERSION=0.30.0-1
ARG SGXSDK_VERSION=2_22_100

RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee -a /etc/apt/sources.list.d/intel-sgx.list \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/occlum.gpg] https://occlum.io/occlum-package-repos/debian focal main" | tee -a /etc/apt/sources.list.d/occlum.list \
 && wget -qO - https://occlum.io/occlum-package-repos/debian/public.key | gpg --dearmor --output /usr/share/keyrings/occlum.gpg \
 && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg \
 && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99sgx_${SGXSDK_VERSION}_focal_custom_version.cfg | tee -a /etc/apt/preferences.d/99sgx_sdk \
 && apt-get update \
 && env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libsgx-uae-service \
    libsgx-dcap-ql \
    libsgx-dcap-quote-verify \
    libsgx-quote-ex \
    libsgx-dcap-default-qpl \
    tzdata \
    libfuse2 \
    libfuse3-3

WORKDIR /opt/occlum/sgxsdk-tools
COPY --from=builder /opt/occlum/sgxsdk-tools .

WORKDIR /opt/occlum/build/bin
COPY --from=builder /opt/occlum/build/bin/occlum .
COPY --from=builder /opt/occlum/build/bin/occlum-run .
COPY --from=builder /opt/occlum/build/bin/occlum_build.mk .
COPY --from=builder /opt/occlum/build/bin/occlum_exec_client .
COPY --from=builder /opt/occlum/build/bin/occlum_exec_server .
RUN echo 'export PATH="/opt/occlum/build/bin:$PATH"' > /etc/profile.d/occlum-runtime.sh

WORKDIR /run/rune
COPY --from=builder /run/unified/occlum_instance/occlum_instance.tar.gz .

RUN tar xf occlum_instance.tar.gz && \
    echo "/run/rune/occlum_instance/build/lib/" | tee /etc/ld.so.conf.d/occlum-pal.conf && \
    echo "/opt/occlum/sgxsdk-tools/sdk_libs/" | tee -a /etc/ld.so.conf.d/occlum-pal.conf && \
    ldconfig && \
    /opt/occlum/sgxsdk-tools/bin/x64/sgx_sign dump -dumpfile /run/agent.txt -cssfile /run/sigstruct1.bin -enclave occlum_instance/build/lib/libocclum-libos.signed.so && \
    mkdir /configs && \
    rm *.tar.gz
