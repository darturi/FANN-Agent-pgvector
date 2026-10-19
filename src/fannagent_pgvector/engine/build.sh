#!/usr/bin/env bash
set -euo pipefail

repository="https://github.com/pgvector/pgvector.git"
commit="8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c"
image="${1:-fannagent/pgvector:0.8.6-secure-v1}"
engine_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checkout="$(mktemp -d "${TMPDIR:-/tmp}/fannagent-pgvector.XXXXXX")"
postgres_checkout="$(mktemp -d "${TMPDIR:-/tmp}/fannagent-postgres.XXXXXX")"

cleanup() { rm -rf "${checkout}" "${postgres_checkout}"; }
trap cleanup EXIT

git clone --filter=blob:none "${repository}" "${checkout}"
git -C "${checkout}" checkout --detach "${commit}"
for patch in \
  "${engine_dir}/patches/0001-same-execution-observability.patch" \
  "${engine_dir}/patches/0002-paper-informed-evidence.patch" \
  "${engine_dir}/patches/0003-close-remaining-gaps.patch" \
  "${engine_dir}/patches/0004-existing-target-binding.patch" \
  "${engine_dir}/patches/0005-reviews-runtime-fixes.patch" \
  "${engine_dir}/patches/0006-demand-frontier-statistics.patch"; do
  git -C "${checkout}" apply --check "${patch}"
  git -C "${checkout}" apply "${patch}"
done
cp "${engine_dir}/Dockerfile" "${checkout}/Dockerfile"
cp "${engine_dir}/copy.nft" "${checkout}/copy.nft"
cp "${engine_dir}/proxy.nft" "${checkout}/proxy.nft"
cp "${engine_dir}/copy-entrypoint.sh" "${checkout}/copy-entrypoint.sh"
cp "${engine_dir}/postgresql-17.11-executor.patch" "${checkout}/postgresql-17.11-executor.patch"
git clone --filter=blob:none --depth 1 --branch REL_17_11 \
  https://github.com/postgres/postgres.git "${postgres_checkout}"
test "$(git -C "${postgres_checkout}" rev-parse HEAD)" = \
  083ac033419f690758508e08c1736089384bbee8
mkdir "${checkout}/postgres-source"
git -C "${postgres_checkout}" archive HEAD | tar -x -C "${checkout}/postgres-source"
printf '%s\n' 083ac033419f690758508e08c1736089384bbee8 \
  > "${checkout}/postgres-source-commit.txt"
cp -R "${engine_dir}/licenses" "${checkout}/licenses"
docker build --file "${checkout}/Dockerfile" --tag "${image}" "${checkout}"
docker image inspect "${image}" --format '{{.Id}}'
