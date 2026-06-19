#!/usr/bin/env bash
#
# Run the MultiNodeJWKCache benchmark.
#
# It recompiles and re-resolves the classpath once, then runs the benchmark N times.
# Source changes are always picked up (no stale cache to remember to rebuild).
#
# Usage:
#   ./bench_cache.sh [-n RUNS] [JVM args / -Dbench.* knobs ...]
#
# Examples:
#   ./bench_cache.sh -Dbench.mode=both -Dbench.out=bench-results/run.md
#   ./bench_cache.sh -n 5 -Dbench.format=csv -Dbench.out=bench-results/runs.csv
#   ./bench_cache.sh -Dbench.mode=count -Dbench.writers=0
#   ./bench_cache.sh -XX:+PrintCompilation -Dbench.mode=count          # clean HotSpot JIT logging
#   ./bench_cache.sh -Xmx2g -Dbench.readers=4000 -Dbench.measureSec=60
#
set -euo pipefail

cd "$(dirname "$0")"
readonly ROOT="$PWD"
readonly MAIN=org.jetbrains.teamcity.builds.oidc.cache.bench.JWKCacheBenchmarkKt

# Parse -n RUNS from the argument list; all other args are forwarded to the JVM.
RUNS=1
JAVA_ARGS=()
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-n" ]]; then
        shift
        RUNS="$1"
    else
        JAVA_ARGS+=("$1")
    fi
    shift
done

# build-classpath writes only the classpath (no Maven log noise) to a temp file; absolute path because a
# relative -Dmdep.outputFile resolves against the module dir (server/), not here.
mkdir -p "$ROOT/server/target"
cp_file="$(mktemp "$ROOT/server/target/bench-cp.XXXXXX")"
trap 'rm -f "$cp_file"' EXIT

# Compile once, then resolve the classpath. With -am both api and server run build-classpath,
# writing to the same file in dependency order, so it ends with server's (full, test-scope) classpath.
echo ">>> Compiling + resolving classpath via Maven..." >&2
mvn -q -pl server -am test-compile dependency:build-classpath -Dmdep.outputFile="$cp_file" -DincludeScope=test

CP="server/target/test-classes:server/target/classes:$(cat "$cp_file")"
rm -f "$cp_file"

# Default heap first so any -Xmx the caller passes overrides it (last wins on HotSpot).
# All caller args (JVM flags + -Dbench.* system properties) go before the main class.
for ((run=1; run<=RUNS; run++)); do
    [[ $RUNS -gt 1 ]] && echo ">>> Run $run of $RUNS ..." >&2
    java -Xmx1g -XX:+EnableDynamicAgentLoading -cp "$CP" "${JAVA_ARGS[@]}" "$MAIN"
done
