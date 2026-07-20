# To specify an alternate base image: --build-arg BASE_IMAGE="some/other/image:tag"
ARG BASE_IMAGE="ubuntu:22.04"

# Version of QEMU to build from source. Distro packages (e.g. Ubuntu's
# qemu-kvm) typically lag several years behind upstream, so we build the
# latest stable QEMU release ourselves instead. See
# doc/content/articles/vmtypes.article for compatibility notes.
ARG QEMU_VERSION="11.0.2"

# -- go builder --
FROM golang:1.24.13 AS gobuilder

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /minimega/

COPY . .

RUN ./scripts/all.bash


# -- qemu builder --
# Builds QEMU from source against the same base image used for the runtime
# image below so that the resulting binaries are ABI-compatible with the
# libraries available at runtime.
FROM ${BASE_IMAGE} AS qemubuilder
ARG QEMU_VERSION

ENV DEBIAN_FRONTEND="noninteractive"

# ninja-build and pkg-config are used directly; QEMU's configure script
# manages its own Python venv and will fetch a suitable version of meson
# into it if the one on the system (if any) is too old. python3-tomli is
# needed because QEMU's build tooling requires "tomllib", which is only
# built into Python 3.11+ (Ubuntu 22.04 ships Python 3.10).
RUN apt-get update && apt-get install -y \
      build-essential ninja-build pkg-config \
      python3 python3-venv python3-pip \
      libglib2.0-dev libpixman-1-dev zlib1g-dev \
      libspice-protocol-dev flex bison python3-tomli \
      git ca-certificates curl xz-utils \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL "https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz" -o qemu.tar.xz \
  && tar xf qemu.tar.xz \
  && rm qemu.tar.xz

# minimega only ever launches the x86_64 system emulator under KVM, so we
# restrict the target list to keep the build time down considerably compared
# to building every target QEMU supports. --disable-fdt avoids needing to
# fetch the dtc subproject, which is unused by x86 PC machine types anyway.
RUN cd "qemu-${QEMU_VERSION}" \
  && ./configure \
       --prefix=/usr/local \
       --target-list=x86_64-softmmu \
       --enable-kvm \
       --disable-slirp \
       --disable-docs \
       --disable-gtk \
       --disable-sdl \
       --disable-spice \
       --disable-fdt \
  && make -j"$(nproc)" \
  && make install

# minimega defaults to invoking a `kvm` binary (see `vm config qemu`),
# matching the wrapper historically provided by Debian/Ubuntu's qemu-kvm
# package. Recreate that wrapper on top of the binary we just built.
RUN printf '#!/bin/sh\nexec /usr/local/bin/qemu-system-x86_64 -enable-kvm "$@"\n' \
      > /usr/local/bin/kvm \
  && chmod +x /usr/local/bin/kvm


# -- minimega image --
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND="noninteractive" \
    PATH="$PATH:/opt/minimega/bin"

RUN apt-get update \
  && apt-get install -y \
    dnsmasq iproute2 isc-dhcp-client \
    libpcap-dev ntfs-3g openssh-client \
    openvswitch-switch \
    iptables ffmpeg \
    libglib2.0-0 libpixman-1-0 zlib1g \
  && apt autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /var/cache/apt/archives/*

# QEMU: qemu-system-x86_64, qemu-img, qemu-nbd, and the `kvm` wrapper, built
# from source in the qemubuilder stage above (along with the firmware blobs
# it needs, e.g. SeaBIOS/OVMF) so that minimega runs against the latest
# stable QEMU release rather than the version packaged by the distro.
COPY --from=qemubuilder /usr/local/bin/qemu-system-x86_64 /usr/local/bin/qemu-system-x86_64
COPY --from=qemubuilder /usr/local/bin/qemu-img /usr/local/bin/qemu-img
COPY --from=qemubuilder /usr/local/bin/qemu-nbd /usr/local/bin/qemu-nbd
COPY --from=qemubuilder /usr/local/bin/kvm /usr/local/bin/kvm
COPY --from=qemubuilder /usr/local/share/qemu /usr/local/share/qemu

# Copy all binaries, including tools such as vmbetter, rfbplay and vncdrone
# While this includes some tools like minitest that generally aren't
# needed in a deployment, the disk utilization difference is minimal,
# and ensures any future tools get included in the Docker image.
COPY --from=gobuilder /minimega/bin/ /opt/minimega/bin/

# As the minimega API changes, so does the minimega.py generated file. Given
# this, let's go ahead and also include the lib directory so we can grab the
# updated Python package from the Docker image.
COPY --from=gobuilder /minimega/lib       /opt/minimega/lib
COPY --from=gobuilder /minimega/README.md /opt/minimega/lib/README.md
COPY --from=gobuilder /minimega/VERSION   /opt/minimega/lib/VERSION

# Copy files from source tree
COPY ./web /opt/minimega/web
COPY ./docker/mm /usr/local/bin/mm
COPY ./docker/start-minimega.sh /start-minimega.sh

RUN chmod +x /usr/local/bin/mm \
  && chmod +x /start-minimega.sh

WORKDIR /opt/minimega

CMD ["/start-minimega.sh"]
