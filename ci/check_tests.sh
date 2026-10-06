#!/bin/sh
# Test-floor guard: run the unit tests, then verify the test manifest.
#
# Zig 0.16 has no coverage instrumentation, so the floor is enforced by a
# manifest instead: (a) a minimum count of `test "` blocks across src/, and
# (b) the required presence of the HTTP framing test names (socketpair-
# driven readHttpRequest coverage plus the pure-function edge cases).
#
# When you add tests, bump MIN_TESTS and extend REQUIRED_TESTS in the same
# PR. Lowering either is a maintainer decision, not a mechanical fix.
#
# Runs from the repo root. The zig binary comes from $ZIG or PATH.
set -eu

ZIG_BIN="${ZIG:-zig}"

# --- run the suite ---------------------------------------------------------
"$ZIG_BIN" build test

# --- test count floor ------------------------------------------------------
MIN_TESTS=142
TEST_COUNT=$(grep -rh 'test "' src/ --include='*.zig' | wc -l | tr -d ' ')
if [ "$TEST_COUNT" -lt "$MIN_TESTS" ]; then
    echo "check_tests: test block count $TEST_COUNT is below floor $MIN_TESTS" >&2
    exit 1
fi
echo "check_tests: $TEST_COUNT test blocks (floor $MIN_TESTS)"

# --- required test names ---------------------------------------------------
REQUIRED_TESTS='read http request extracts full post request
read http request extracts lowercase header names
read http request body containing crlfcrlf sequence
read http request sends 100 continue for expect header
read http request ignores non continue expect value
read http request skips 100 continue without body
read http request rejects malformed content length
read http request rejects conflicting duplicate content length
read http request rejects oversized content length
read http request short body after eof errors
read http request unterminated headers error on eof
read http request clean eof on empty socket
read http request oversized headers rejected
read http request rejects malformed request line
read http request keeps pipelined bytes as carry for the next request
read http request rejects chunked transfer encoding
read http request without content length has empty body
content length rejects malformed values and documents plus prefix
expect continue matching is case insensitive and whitespace trimmed
audit canonical line bytes are fixed order and whitespace free
audit mac chain over three records verifies
audit verifier detects edit
audit verifier detects deletion
audit verifier detects reorder
audit tail recovery continues the chain after reopen
audit corrupt tail starts a new file with chain.break
audit ring block policy waits for space then drains
audit ring drop policy counts drops and logs a dropped record
audit args summary never contains script or content
audit summary mode logs argv0 and argc only
audit keyless mode writes chain:false without mac and verifies seq only
audit verify of a chained file without the key fails closed
audit start and stop records frame a run
audit req_id truncation keeps valid json
audit relay and link event shapes stay inside the record budget
audit rotation chains files by prev across the rename
config audit env parsing and the key/file pairing rule
command line: audit-verify subcommand'

status=0
while IFS= read -r name; do
    [ -n "$name" ] || continue
    if ! grep -rqF "test \"$name\"" src/; then
        echo "check_tests: missing required test: $name" >&2
        status=1
    fi
done <<EOF
$REQUIRED_TESTS
EOF

if [ "$status" -ne 0 ]; then
    echo "check_tests: framing test manifest is incomplete" >&2
    exit 1
fi
echo "check_tests: framing test manifest OK"
