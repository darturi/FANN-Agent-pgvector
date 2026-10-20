FROM fannagent/pgvector-reviews-toolchain:20261013 AS extension
COPY engine-source/src/fannbench.c /tmp/pgvector/src/fannbench.c
COPY engine-source/src/fannbench.h /tmp/pgvector/src/fannbench.h
RUN cd /tmp/pgvector && make clean >/dev/null && make OPTFLAGS="" >/tmp/build.log 2>&1 && make install DESTDIR=/opt/predicate-candidate >/dev/null
FROM fannagent/queue-statistics-fixture:20261019
USER root
COPY --from=extension /opt/predicate-candidate/usr/lib/postgresql/17/lib/vector.so /opt/predicate-fixture/candidate-vector.so
ENTRYPOINT []
