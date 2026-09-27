FROM @BASE@
ARG DEBIAN_FRONTEND=noninteractive
COPY packages/ /packages/
RUN dpkg --add-architecture i386 \
    && apt-get --yes --no-install-recommends install /packages/*.deb \
    && rm -rf /packages /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash wine \
    && install -d -o wine -g wine -m 0755 /wine /work
COPY --chmod=0755 entrypoint.sh /usr/local/bin/squatter-wine-entrypoint
ENV WINEDEBUG=-all WINEPREFIX=/wine LANG=C.UTF-8 LC_ALL=C.UTF-8 SQUATTER_EXE=/payload/squatter.exe SQUATTER_PORT=9100
LABEL org.opencontainers.image.source="https://github.com/vibepwners/hovel"
WORKDIR /work
USER wine
EXPOSE 9100
ENTRYPOINT ["/usr/local/bin/squatter-wine-entrypoint"]
