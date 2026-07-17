FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget gnupg \
    && install -d -m 0755 /etc/apt/keyrings \
    && wget -qO /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -qNP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources \
    && apt-get update \
    && apt-get install -y --install-recommends winehq-stable \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash wine \
    && install -d -o wine -g wine -m 0755 /wine /work

COPY entrypoint.sh /usr/local/bin/squatter-wine-entrypoint

ENV WINEDEBUG=-all \
    WINEPREFIX=/wine \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    SQUATTER_EXE=/payload/squatter.exe \
    SQUATTER_PORT=9100

WORKDIR /work
EXPOSE 9100

USER wine

ENTRYPOINT ["/usr/local/bin/squatter-wine-entrypoint"]
