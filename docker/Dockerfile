# To specify an alternate base image: --build-arg BASE_IMAGE="some/other/base_image:tag"
# To specify an alternate Go image: --build-arg GO_IMAGE="some/other/go_image:tag"
ARG BASE_IMAGE="ubuntu:24.04"
ARG GO_IMAGE="golang:1.24.13"
ARG PYTHON_IMAGE="python:3.13-slim"
# QEMU_SOURCE="upstream" copies QEMU from QEMU_IMAGE (built by docker/qemu/Dockerfile);
# QEMU_SOURCE="distro" installs the Ubuntu QEMU packages instead.
ARG QEMU_IMAGE="ghcr.io/sandia-minimega/qemu-build:11.1.3-noble-1"
ARG QEMU_SOURCE="upstream"
ARG QEMU_VERSION="11.1.3"

# -- go builder --
FROM ${GO_IMAGE} AS gobuilder

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /minimega/

COPY . .

RUN ./scripts/all.bash

# Resolve the LICENSES symlinks, which point into web/, as the packages do.
RUN mkdir -p /licenses && cp -rL LICENSE LICENSES /licenses/


# -- documentation builder --
FROM ${PYTHON_IMAGE} AS docbuilder

WORKDIR /minimega/

COPY zensical.toml ./
COPY doc/requirements.txt ./doc/requirements.txt
COPY scripts/zensical_build.py ./scripts/zensical_build.py
COPY doc/pygments_minimega ./doc/pygments_minimega
RUN apt-get update \
  && apt-get install -y --no-install-recommends git \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir -r doc/requirements.txt

COPY --from=gobuilder /minimega/doc/content ./doc/content
COPY --from=gobuilder /minimega/doc/overrides ./doc/overrides
COPY --from=gobuilder /minimega/lib/minimega.py ./lib/minimega.py
COPY --from=gobuilder /minimega/.git ./.git
RUN python scripts/zensical_build.py build --strict


# -- QEMU, selected by QEMU_SOURCE --
# Each stage has /out (copied to /) and /out-packages (Ubuntu packages to install).
FROM ${QEMU_IMAGE} AS qemu-upstream

FROM ${BASE_IMAGE} AS qemu-distro
RUN mkdir /out && echo "qemu-system-x86 qemu-utils" > /out-packages

# The base is one of the two stages above, not a registry image.
# hadolint ignore=DL3006
FROM qemu-${QEMU_SOURCE} AS qemu


# -- minimega image --
FROM ${BASE_IMAGE}

ARG QEMU_SOURCE
ARG QEMU_VERSION

ENV DEBIAN_FRONTEND="noninteractive" \
    PATH="$PATH:/opt/minimega/bin"

COPY --from=qemu /out-packages /tmp/qemu-packages

# libxkbfile1: the Android emulator (vm launch android, with the Android SDK
# mounted into the container) links against it.
# hadolint ignore=SC2046
RUN apt-get update \
  && apt-get install -y \
    bash-completion dnsmasq iproute2 isc-dhcp-client \
    less libpcap-dev ntfs-3g openssh-client \
    openvswitch-switch \
    iptables ffmpeg \
    libxkbfile1 \
    $(cat /tmp/qemu-packages) \
  && rm /tmp/qemu-packages \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /var/cache/apt/archives/*

COPY --from=qemu /out/ /
COPY ./docker/check-qemu.sh /usr/local/bin/check-qemu.sh
RUN /usr/local/bin/check-qemu.sh "$QEMU_SOURCE" "$QEMU_VERSION"

# Copy all binaries, including tools such as vmbetter, rfbplay and vncdrone
# While this includes some tools like minitest that generally aren't
# needed in a deployment, the disk utilization difference is minimal,
# and ensures any future tools get included in the Docker image.
COPY --from=gobuilder /minimega/bin/ /opt/minimega/bin/
COPY --from=gobuilder /licenses/ /usr/share/doc/minimega/

# Pre-generate the bash tab-completion script so it's available out of the
# box for interactive shells inside the container (e.g. `docker exec -it
# minimega bash`), picked up automatically via the bash-completion package
# installed above.
RUN mkdir -p /usr/share/bash-completion/completions \
  && /opt/minimega/bin/minimega -completion bash > /usr/share/bash-completion/completions/minimega

# As the minimega API changes, so does the minimega.py generated file. Given
# this, let's go ahead and also include the lib directory so we can grab the
# updated Python package from the Docker image.
COPY --from=gobuilder /minimega/lib       /opt/minimega/lib

# Copy files from source tree
COPY ./web /opt/minimega/web
COPY --from=docbuilder /minimega/site /opt/minimega/web/docs
COPY ./docker/mm /usr/local/bin/mm
COPY ./docker/start-minimega.sh /start-minimega.sh

RUN ln -s /opt/minimega/web/docs /opt/minimega/docs \
  && chmod +x /usr/local/bin/mm \
  && chmod +x /start-minimega.sh

WORKDIR /opt/minimega

CMD ["/start-minimega.sh"]
