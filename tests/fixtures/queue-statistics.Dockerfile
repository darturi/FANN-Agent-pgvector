# Build context: a disposable patched pgvector checkout, never an existing database.
FROM fannagent/pgvector-reviews-toolchain:20261013 AS extension
COPY src/ /tmp/pgvector/src/
RUN cd /tmp/pgvector && make clean && make OPTFLAGS="" && \
    make install DESTDIR=/opt/queue-candidate

FROM fannagent/pgvector:reviews-development-fixes-5c054206c0b4 AS baseline

FROM baseline AS runtime
COPY --from=extension /opt/queue-candidate/ /
LABEL io.fannagent.queue_statistics="sort-on-demand-v1"

FROM baseline AS fixture-python
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates && python3 -m venv /opt/size-fixture-python && /opt/size-fixture-python/bin/pip install --no-cache-dir numpy pyarrow 'psycopg[binary]' pydantic PyYAML && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/queue-fixture && \
    cp -a /usr/lib/postgresql/17/lib /opt/queue-fixture/baseline-lib
ENV PATH="/opt/size-fixture-python/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1

FROM fixture-python AS fixture
COPY --from=extension /opt/queue-candidate/usr/lib/postgresql/17/lib/vector.so /opt/queue-fixture/candidate-vector.so
ENTRYPOINT []
