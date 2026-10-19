"""Compile the packaged C collector and compare it with the committed baseline."""

import ctypes
import hashlib
import json
import math
import random
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

ENGINE = Path(__file__).parents[1] / "src/fannagent_pgvector/engine"


def function(source, name):
    start = re.search(r"^(?:static )?(?:void|int|double)\n" + name + r"\(", source, re.M)
    assert start, name
    opening = source.index("{", start.start())
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start.start() : end]


@pytest.fixture(scope="module")
def collectors(tmp_path_factory):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for native collector equivalence")
    root = tmp_path_factory.mktemp("frontier-collector")
    provenance = json.loads((ENGINE / "provenance.json").read_text())
    baseline = None
    for patch in provenance["patches"]:
        path = ENGINE / patch["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == patch["sha256"]
        subprocess.run(
            ["git", "apply", "--include=src/fannbench.c", str(path)], cwd=root, check=True
        )
        if path.name.startswith("0005-"):
            baseline = (root / "src/fannbench.c").read_text()
    optimized = (root / "src/fannbench.c").read_text()
    assert baseline is not None
    names = (
        "featureCollectionNanos",
        "frontierSnapshotCount",
        "frontierValuesCopied",
        "frontierMaximumCount",
        "frontierTraversalNanos",
        "frontierStatisticsNanos",
        "frontierSortCount",
        "frontierSortNanos",
        "frontierQuantileNanos",
    )
    header = r"""
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
typedef int64_t int64;
typedef uint64_t instr_time;
static uint64_t now_ns(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
#define INSTR_TIME_SET_CURRENT(value) ((value) = now_ns())
#define INSTR_TIME_SUBTRACT(value, previous) ((value) -= (previous))
#define INSTR_TIME_GET_NANOSEC(value) (value)
static struct {
    bool active, hasFrontierStats, queueQuantilesEnabled;
    char traceLevel[16];
    double frontierStats[7];
    int64 COUNTERS;
} executionState;
""".replace("COUNTERS", ", ".join(names))
    helpers = function(baseline, "CompareQueueDistance") + function(baseline, "QueuePercentile")
    legacy = function(baseline, "FannbenchHnswSetFrontierDistances").replace(
        "FannbenchHnswSetFrontierDistances", "collect_baseline"
    )
    candidate = function(optimized, "FannbenchHnswSetFrontierDistances").replace(
        "FannbenchHnswSetFrontierDistances", "collect_optimized"
    )
    wrapper = r"""
void reset_state(int active, int quantiles, int trace) {
    memset(&executionState, 0, sizeof(executionState));
    executionState.active = active;
    executionState.queueQuantilesEnabled = quantiles;
    strcpy(executionState.traceLevel, trace ? "checkpoints" : "off");
}
int available(void) { return executionState.hasFrontierStats; }
double feature(int index) { return executionState.frontierStats[index]; }
int64 counter(int index) {
    int64 values[] = {COUNTERS};
    return values[index];
}
""".replace("COUNTERS", ", ".join("executionState." + n for n in names))
    source = root / "collector.c"
    source.write_text(header + helpers + legacy + candidate + wrapper)
    library = root / "collector.so"
    subprocess.run(
        [compiler, "-O2", "-std=c99", "-fPIC", "-shared", str(source), "-lm", "-o", str(library)],
        check=True,
    )
    lib = ctypes.CDLL(str(library))
    for name in ("collect_baseline", "collect_optimized"):
        getattr(lib, name).argtypes = [
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_int,
            ctypes.c_int64,
        ]
    lib.reset_state.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.feature.argtypes = [ctypes.c_int]
    lib.feature.restype = ctypes.c_double
    lib.counter.argtypes = [ctypes.c_int]
    lib.counter.restype = ctypes.c_int64

    def collect(values, *, old=False, quantiles=False, trace=False, active=True):
        lib.reset_state(active, quantiles, trace)
        data = (ctypes.c_double * len(values))(*values)
        callback = lib.collect_baseline if old else lib.collect_optimized
        callback(data, len(values), 1234)
        return {
            "available": bool(lib.available()),
            "values": [lib.feature(i) for i in range(7)],
            "counters": {n: lib.counter(i) for i, n in enumerate(names)},
        }

    return collect


@pytest.mark.parametrize("quantiles,trace", [(False, False), (True, False), (False, True)])
def test_actual_c_statistics_match_baseline_bitwise(collectors, quantiles, trace):
    rng = random.Random(20261019)
    populations = [[1.0], [0.0, 2.0], [0.1] * 31, [2.0, 0.0, 1.0, 1.0]]
    populations += [[rng.random() * 2 for _ in range(n)] for n in (3, 64, 320, 4096, 10000)]
    for values in populations:
        old = collectors(values, old=True, quantiles=quantiles, trace=trace)
        new = collectors(values, quantiles=quantiles, trace=trace)
        assert old["available"] == new["available"] is True
        for a, b in zip(
            old["values"][: 7 if quantiles or trace else 4],
            new["values"][: 7 if quantiles or trace else 4],
            strict=True,
        ):
            assert struct.pack("d", a) == struct.pack("d", b)
        counters = new["counters"]
        assert counters["frontierSnapshotCount"] == 1
        assert counters["frontierValuesCopied"] == counters["frontierMaximumCount"] == len(values)
        assert counters["frontierTraversalNanos"] == 1234
        assert counters["frontierSortCount"] == int(quantiles or trace)
        if not (quantiles or trace):
            assert counters["frontierSortNanos"] == counters["frontierQuantileNanos"] == 0
        assert (
            sum(
                counters[n]
                for n in (
                    "frontierTraversalNanos",
                    "frontierStatisticsNanos",
                    "frontierSortNanos",
                    "frontierQuantileNanos",
                )
            )
            <= counters["featureCollectionNanos"]
        )


def test_numeric_decisions_at_adjacent_float_thresholds(collectors):
    values = [0.125, 0.25, 0.25, 0.875, 1.0, 1.75, 2.0]
    old = collectors(values, old=True)["values"]
    new = collectors(values)["values"]
    for index in (0, 1, 2, 3):
        value = old[index]
        for threshold in (math.nextafter(value, -math.inf), value, math.nextafter(value, math.inf)):
            assert (old[index] >= threshold) == (new[index] >= threshold)
            assert (old[index] == threshold) == (new[index] == threshold)


@pytest.mark.parametrize("values", [[], [math.nan], [math.inf], [-math.inf], [1.0, math.nan]])
def test_unavailable_populations_preserve_baseline_behavior(collectors, values):
    assert collectors(values)["available"] is collectors(values, old=True)["available"] is False


def test_inactive_execution_remains_unavailable(collectors):
    result = collectors([0.5, 1.0], active=False)
    assert not result["available"]
    assert result["counters"]["frontierSnapshotCount"] == 0
