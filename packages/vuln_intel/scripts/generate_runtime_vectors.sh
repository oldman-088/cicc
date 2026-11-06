#!/usr/bin/env bash
# Generate Maven and RubyGems ordering vectors from the *real* implementations.
#
# This is the missing half of B-17. The Python suite currently checks Maven against
# Apache's `ComparableVersionTest` and RubyGems against `test_gem_version.rb` — both
# upstream test suites, which is strong but is not a cross-check against a running
# implementation. This script runs the real `ComparableVersion` and the real
# `Gem::Version` over the same permutation corpus the Python oracle uses, and writes
# the answers to a JSON file that a test can then diff against our own comparators.
#
# Requirements: a JVM (java 11+), a Ruby (2.7+), and Maven's maven-artifact jar, which
# this script downloads from Maven Central (Apache-2.0).
#
# Nothing here runs in the default CI job. It is opt-in because it needs a JVM and a
# Ruby, and adding both to the Python job for two comparators was not a trade worth
# making silently. See docs/vulnerability-intelligence/ORACLE_VALIDATION.md §7.
#
# Usage (from packages/vuln_intel):
#   ./scripts/generate_runtime_vectors.sh            # write tests/fixtures/runtime_vectors.json
#   ./scripts/generate_runtime_vectors.sh --check    # fail if the file is stale
#
# The output file records the exact java and ruby versions that produced it, so a
# reader can tell which runtime the answers came from.

set -euo pipefail

MAVEN_ARTIFACT_VERSION="3.9.9"
MAVEN_CENTRAL="https://repo1.maven.org/maven2"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package_root="$(dirname "$here")"
out_file="${package_root}/tests/fixtures/runtime_vectors.json"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

check_mode=0
if [[ "${1:-}" == "--check" ]]; then
  check_mode=1
fi

# -- requirements -------------------------------------------------------------
missing=()
command -v java >/dev/null 2>&1 || missing+=("java (JDK 11+)")
command -v javac >/dev/null 2>&1 || missing+=("javac (JDK 11+)")
command -v ruby >/dev/null 2>&1 || missing+=("ruby (2.7+)")
command -v curl >/dev/null 2>&1 || missing+=("curl")
if (( ${#missing[@]} )); then
  printf 'Cannot generate runtime vectors; missing: %s\n' "${missing[*]}" >&2
  printf 'This is the documented B-17 limitation. The upstream-vector tests still run.\n' >&2
  exit 2
fi

echo "java:  $(java -version 2>&1 | head -1)"
echo "ruby:  $(ruby -v)"

# -- the corpus ---------------------------------------------------------------
# Deliberately the same shapes the Python oracle covers, plus the cases where the two
# ecosystems differ from each other: Maven's '-' sublists and qualifier aliases,
# RubyGems' letter segments and case sensitivity.
read -r -d '' CORPUS <<'CORPUS_EOF' || true
1
1.0
1.0.0
1.0.1
1.1
1.2.3
1-1
1-0
1-rc
1-rc1
1-cr1
1-alpha
1-alpha1
1-a1
1-beta
1-b1
1-m1
1-milestone1
1-sp
1-ga
1-final
1-snapshot
2.0
2.0.1
2.0.1-xyz
2.0.1-1
2.0.1.1
1.0-alpha-1
1.0-alpha-2
1.0-alpha1
1.0-beta
1.0-rc1
3.0.0
3.0.0.0
5.x
5.0.0.rc2
0.beta.1
0.0.beta.1
1.A
1.a
1.0.0.a
1.0.0
1.0
10.0
9.0
1.0.0.0.0
CORPUS_EOF

mapfile -t versions < <(printf '%s\n' "$CORPUS" | sed '/^$/d')
echo "corpus: ${#versions[@]} versions -> $(( ${#versions[@]} * ${#versions[@]} )) ordered pairs"

# -- Maven --------------------------------------------------------------------
jar="${work_dir}/maven-artifact.jar"
echo "downloading maven-artifact ${MAVEN_ARTIFACT_VERSION} ..."
curl -fsSL -o "$jar" \
  "${MAVEN_CENTRAL}/org/apache/maven/maven-artifact/${MAVEN_ARTIFACT_VERSION}/maven-artifact-${MAVEN_ARTIFACT_VERSION}.jar"

cat > "${work_dir}/MavenVectors.java" <<'JAVA_EOF'
import java.io.*;
import java.util.*;
import org.apache.maven.artifact.versioning.ComparableVersion;

public final class MavenVectors {
    public static void main(String[] args) throws IOException {
        List<String> versions = new ArrayList<>();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty()) versions.add(line);
        }
        StringBuilder out = new StringBuilder();
        out.append("{\"pairs\":[");
        boolean first = true;
        for (String a : versions) {
            for (String b : versions) {
                int cmp;
                try {
                    // Integer.signum keeps the output to -1/0/1: ComparableVersion's
                    // raw return value is unspecified beyond its sign.
                    cmp = Integer.signum(new ComparableVersion(a).compareTo(new ComparableVersion(b)));
                } catch (RuntimeException e) {
                    continue;
                }
                if (!first) out.append(",");
                first = false;
                out.append("[\"").append(escape(a)).append("\",\"")
                   .append(escape(b)).append("\",").append(cmp).append("]");
            }
        }
        out.append("]}");
        System.out.println(out);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
JAVA_EOF

javac -cp "$jar" -d "$work_dir" "${work_dir}/MavenVectors.java"
printf '%s\n' "${versions[@]}" | java -cp "$jar:${work_dir}" MavenVectors > "${work_dir}/maven.json"

# -- RubyGems -----------------------------------------------------------------
cat > "${work_dir}/rubygems_vectors.rb" <<'RUBY_EOF'
require 'json'

versions = STDIN.read.split("\n").map(&:strip).reject(&:empty?)
pairs = []
versions.each do |a|
  versions.each do |b|
    begin
      cmp = Gem::Version.new(a) <=> Gem::Version.new(b)
      cmp = cmp <=> 0   # normalise to -1/0/1
    rescue ArgumentError
      next
    end
    pairs << [a, b, cmp]
  end
end
puts JSON.generate({ 'pairs' => pairs })
RUBY_EOF

printf '%s\n' "${versions[@]}" | ruby "${work_dir}/rubygems_vectors.rb" > "${work_dir}/rubygems.json"

# -- combine ------------------------------------------------------------------
mkdir -p "$(dirname "$out_file")"
"${PYTHON:-python3}" - "${work_dir}/maven.json" "${work_dir}/rubygems.json" "$out_file" <<'PY_EOF'
import json
import subprocess
import sys
from datetime import datetime, timezone

maven_path, rubygems_path, out_path = sys.argv[1:4]
maven = json.load(open(maven_path))
rubygems = json.load(open(rubygems_path))

def version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.splitlines()[0].strip()
    except (OSError, IndexError):
        return None

payload = {
    "schema": "cicc.vuln_intel.runtime_vectors.v1",
    "description": (
        "Ordering answers produced by the real ComparableVersion and Gem::Version. "
        "This file is evidence of a runtime cross-check; it is generated, never "
        "hand-edited."
    ),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "generator": "scripts/generate_runtime_vectors.sh",
    "runtimes": {
        "java": version(["java", "-version"]),
        "ruby": version(["ruby", "-v"]),
    },
    "maven": maven,
    "rubygems": rubygems,
}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(f"wrote {out_path} ({len(maven['pairs'])} maven pairs, {len(rubygems['pairs'])} rubygems pairs)")
PY_EOF

if (( check_mode )); then
  if git -C "$package_root" diff --quiet -- "$out_file"; then
    echo "runtime vectors are current"
  else
    echo "runtime vectors are STALE: regenerate and commit" >&2
    exit 1
  fi
fi
