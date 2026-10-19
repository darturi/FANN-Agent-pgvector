FROM postgres:17-trixie@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232 AS pgcore

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bison flex git libicu-dev libreadline-dev libssl-dev pkgconf zlib1g-dev
COPY postgres-source /tmp/postgres
COPY postgres-source-commit.txt /tmp/postgres-source-commit.txt
RUN test "$(cat /tmp/postgres-source-commit.txt)" = \
    083ac033419f690758508e08c1736089384bbee8
COPY postgresql-17.11-executor.patch /tmp/postgresql-17.11-executor.patch
RUN cd /tmp/postgres && git apply /tmp/postgresql-17.11-executor.patch && \
    cd /tmp/postgres && \
    ./configure --prefix=/usr --bindir=/usr/lib/postgresql/17/bin \
      --libdir=/usr/lib/postgresql/17/lib \
      --datadir=/usr/share/postgresql/17 \
      --with-system-tzdata=/usr/share/zoneinfo \
      --with-openssl --with-icu \
      --with-extra-version=' (Debian 17.11-1.pgdg13+2)' && \
    make -j4

FROM postgres:17-trixie@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232 AS extension
COPY src/ /tmp/pgvector/src/
COPY sql/ /tmp/pgvector/sql/
COPY Makefile vector.control /tmp/pgvector/
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential postgresql-server-dev-17 && \
    cd /tmp/pgvector && make clean && make OPTFLAGS="" && \
    make install DESTDIR=/opt/fannagent-install

FROM postgres:17-trixie@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232
RUN apt-get update && apt-get install -y --no-install-recommends nftables util-linux socat && \
    rm -rf /var/lib/apt/lists/*
COPY --from=pgcore /tmp/postgres/src/backend/postgres /usr/lib/postgresql/17/bin/postgres
COPY --from=extension /opt/fannagent-install/ /
LABEL org.opencontainers.image.title="FANNAgent pgvector and PostgreSQL"
LABEL org.opencontainers.image.revision="8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c+083ac033419f690758508e08c1736089384bbee8"
LABEL io.fannbench.protocol="same_execution_v4"

COPY licenses/ /usr/share/doc/fannagent/licenses/
LABEL io.fannagent.binding="1" io.fannagent.protocol="same_execution_v4"
COPY copy.nft /usr/local/share/fannagent/copy.nft
COPY proxy.nft /usr/local/share/fannagent/proxy.nft
COPY --chmod=755 copy-entrypoint.sh /usr/local/bin/fannagent-copy-entrypoint
LABEL io.fannagent.copy_security="1" io.fannagent.copy_proxy="1"
ENTRYPOINT ["/usr/local/bin/fannagent-copy-entrypoint"]
CMD ["postgres"]
