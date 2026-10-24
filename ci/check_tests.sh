#!/bin/sh
# Run the Zig unit test suite and verify the expected test manifest.
# Runs from the repo root; uses $ZIG or `zig` from PATH.
set -eu

ZIG_BIN="${ZIG:-zig}"

# --- run the suite ---------------------------------------------------------
"$ZIG_BIN" build test

# --- test count floor ------------------------------------------------------
MIN_TESTS=406
TEST_COUNT=$(grep -rho '^test "[^"]*"' src/ | sort -u | wc -l | tr -d ' ')
if [ "$TEST_COUNT" -lt "$MIN_TESTS" ]; then
    echo "check_tests: test block count $TEST_COUNT is below floor $MIN_TESTS" >&2
    exit 1
fi
echo "check_tests: $TEST_COUNT test blocks (floor $MIN_TESTS)"

# --- required test names ---------------------------------------------------
REQUIRED_TESTS='durable recovery quarantines an incomplete admission
durable combined-stream reservation kills over-budget sessions
durable done-session log growth past the cap is flagged, not signaled
durable periodic sweep kills unpolled writers including recovered sessions
exec_shell path and bare policy entries align without loosening exec
durable spool UTF-8 pages hold live tails and reconcile late recovery bytes
durable spool pages reassemble beyond capture cap with zero loss
durable spool pages survive restart beyond capture cap
ephemeral overflow preserves head kept offsets and lost counters
state enabled tombstones preserve ephemeral expiry and durable ownership
sys_info advertises effective output cap and durable opt in
durable identity resource and read failures remain indeterminate
durable completion reconciles final and late bytes across recovery
durable descendant growth does not seal output complete
durable artifact larger than log reservation remains intact
durable output cap kills writer preserves pages and balances reservation
durable admission refuses insufficient filesystem space without reserving
durable failed admission after commit cannot recover a phantom
durable partial create failure removes files and records tombstone
state enabled close then poll preserves expiry for both backends
durable reservation uses checked arithmetic
durable state directory pins private objects and holds exclusive lock
durable proc stat identity uses last parenthesis and field 22
durable identity tri state and boot mismatch never authorize signals
durable index exact budget round trip and checksum rejection
durable tombstone newest first eviction and owner anti oracle
durable meta exact header offsets round trip and checksum rejection
durable metadata cap counts argv length prefixes
durable boot id UUID uses RFC bytes and Windows rejects trailing half
durable records reject reserved bytes even with valid checksum
durable config CLI wins absolute nonempty and hub refusal
durable config feature off defaults and invalid ceiling
durable command line state directory empty values rejected
read_file line mode selects windows and reports total_lines
write_file accepts plain content and refuses dual or missing content
output shaping matches full stream selection across ring wraps
output shaping XOR includes zero
output shaping empty stream and zero selection
output shaping unterminated line and CRLF
output shaping oversized single line and tail ring
output shaping UTF-8 cuts and chunk boundary splits
output shaping preserves malformed UTF-8 and natural EOF
output shaping strict parameter types and effective cap
output shaping absent and null preserve legacy selection
output shaping bounded heap retention and drain ceiling
output page validation excludes selectors and small limits
output shaping independent streams and omitted algebra
shaped exec and shell drain beyond capture cap with exact counters
shaped timeout returns partial streams counters and null exit
session pages progress across UTF-8 without capture loss
session page holds live partial UTF-8 but flushes malformed EOF
shaped envelope worst case stays below link payload with text mirror
output shaping schemas are additive and nullable exit is advertised
copy: depth cap also applies to regular file descendants
copy: root file content digest
copy: root directory sorted digest golden fixture
copy: destination exists never overwritten
copy: recursive required
copy: zero byte budget accepts empty file
copy: both pins retain separate deny lists
copy: child read deny aborts stage
copy: child write deny aborts stage
copy: fixed file mode masked by policy cap
copy: root symlink refused
copy: descendant symlink refused
copy: destination symlink never followed
copy: hardlink source refused
copy: overlap and identity ancestor guard
copy: source change discards stage
copy: byte cap discards stage and releases gate
copy: entry cap counts root and empty directories
copy: depth cap refuses sixty fifth descendant
copy: publication race preserves concurrent destination
copy: unsupported atomic publish has no rename fallback
copy: expired deadline cleans stage and releases gate
copy: node wide gate rejects concurrent operation
copy: streaming memory independent of payload size
copy: missing parent never created
copy: state directory overlap refused
copy: policy gate preserves symlink spelling
copy: parent traversal rejected before normalization
copy: fifo source refuses without blocking
copy: fallback transfer hashes staged bytes
copy: cleanup failure is explicit and marked stage recovered
copy: unknown stage directory is never scavenged
copy: forged stage marker is never scavenged
copy: unpublishable directory mode cap refuses before staging
copy: state overlap covers destination and ancestor
copy: empty directory digest includes root record
copy: policy gate emits independent read and write pins
copy: timeout cap and tool membership gate before pins
copy: symlink ancestor remains forbidden without policy
copy: destination parent symlink is refused
copy: empty file digest is standard SHA256
copy: accounting hard ceilings reject before side effects
copy: component validation rejects traversal and NUL
copy: audit summaries include both paths but never contents
copy refusal names carry actionable hints
session and exec refusal names carry actionable hints
read http request extracts full post request
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
read http request idle keep-alive timeout closes without 408
read http request oversized headers rejected
read http request rejects malformed request line
read http request keeps pipelined bytes as carry for the next request
read http request rejects chunked transfer encoding
read http request without content length has empty body
content length enforces digit-only grammar
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
audit renderReqId survives a backslash-heavy id
audit tail recovery truncates a torn final line
audit verify with a key refuses a keyless file
audit removing the key between runs starts a new chain
audit session hash is a stable 16 hex prefix
audit wall clock ts is a plausible UTC epoch
audit write failure rolls back and the next batch heals the chain
audit failed rollback retires the handle and recovery re-verifies before writing
audit mid-run tail corruption quarantines and reopens with chain.break
audit recovery onto a vanished file opens with a recover boundary
audit verify refuses a rotated suffix as the first file
audit verify refuses a spliced independent chain at a file boundary
audit verify accepts an explicit chain.break boundary between files
audit verify and recovery refuse seq overflow instead of panicking
audit failed batch preserves the pending chain.break boundary
audit failed batch preserves the pending recover boundary
audit failed sync rolls the batch back and the retry heals the chain
audit rotation refuses to rename away an unsynced file
audit rotation after a chain restart never overwrites old history
audit rotation behind the dir-sync gate commits nothing until the rename is durable
audit quarantine behind the dir-sync gate opens no fresh file until the rename is durable
audit truncated request id is always valid UTF-8 and valid JSON
audit args digest distinguishes invalid UTF-8 byte strings
audit args digest flags deep argument trees as partial
audit args digest never substitutes on numeric formatting
audit args digest frames raw invalid strings against boundary collisions
audit rotation never appends to a foreign file at the freed pathname
audit quarantine gate absorbs a foreign occupant at the freed pathname
audit keyless verify catches a cross-file seq gap
spawn pid registry removes by exact pid and tag pair
registered zombie survives the sweep until its owner unregisters
hub refuses new-name links past the established-link cap
hub stop retracts infrastructure threads and closes the listener
session store shutdownAll joins delayed readers before returning
audit args summary caps the escaped form and flags truncation honestly
audit verify refuses a fresh chain that does not start at seq 0
audit stop terminates under a persistent write failure
audit stop terminates with a held directory-sync gate
config audit env parsing and the key/file pairing rule
command line: audit-verify subcommand
exec kill during a poll-to-read gap keeps output and done after readers
reapStrayChildren collects an unprotected zombie behind a protected one
statIsZombieChild parses state and ppid after the comm field
reapStraysFromProc retries EINTR and parses the following batch
reapStraysFromProc exits safely when getdents fails persistently
reapProcBatch stops on malformed records instead of walking past the batch
FdBox: an explicit close is never repeated (fd numbers get reused)
pinned spawn pipe failure keeps the fork gate balanced and leaks nothing
pinned spawn error path after the fork closes each fd exactly once
runCollected times out on a child that closed its output and lives on
tool exec times out on a child that closed its output and lives on
tool exec_shell times out on a child that closed its output and lives on
tool exec returns the exit code of a child that closed its output and exited
tool exec output beyond max_out still fails with OutputTooLong
sessionRequestClose is one-shot: repeated calls write exactly one wake byte
policy: list_dir default path is gated as the daemon cwd
policy: dangling symlinks in the unresolved tail fail closed
policy: canonicalisation failure denies instead of falling back
policy: prefix lists are canonicalised at load
policy: relative argv0 authorizes against the requested cwd
policy: exec tilde argv0 stays literal and anchors to the cwd
policy: exec tilde cwd gates the literal path from the daemon cwd
policy: relative exec base anchors argv0 to the daemon cwd
policy: exec pin is the authorized canon, canonicalized once
policy: file tool tilde expansion gates the home path
policy: canonicalizePathExec keeps tilde literal and anchors a relative base
secure: swapped prefix (symlink ancestor) is refused
secure: symlink escaping the allow tree is refused (EXDEV)
secure: symlink into a denied subtree is refused by the post-check
secure: legal reads, writes, mkdirs and listing work
secure: F_GETPATH decode returns the nul-terminated path length
secure: F_GETPATH decode fails closed on contract violations
secure: windows path matcher strips the verifier prefix and folds case
secure: windows path matcher normalizes both operands symmetrically
secure: windows argv0 image name follows the CreateProcess extension rule
secure: windows mkdirs walk steps align canon and rel
secure: w16 case fold compares ascii units and nothing wider
secure: fifo target is refused promptly instead of hanging
secure: exe pin fds are cloexec in the parent
secure: in-tree dangling symlink write refuses before creating
fd: readFileAlloc refuses a fifo promptly instead of hanging
fd: writeFile refuses a fifo promptly instead of hanging
rpc payload facts extract ok exit code and error
file tools under a policy list entries without following symlinks
file tools pinned read of a directory answers IsDirectory
policy: argv0 separator detection covers the windows backslash form
file tools under a policy read, write and list through the pin
exec under a policy spawns through the pinned objects
exec_start under a policy spawns the session through the pin
exec swap race after the gate is refused by the pin
pinned exec runs the original object after a post-pin rename
pinned spawn exec failure reaps the child and answers the error
rpc notification tools/call executes the method and answers 202
cross-token session probe releases its borrowed ref
unknown term exit code reinterprets windows NTSTATUS values
secure: windows pin share mask is read+write and no invented bits
secure: write-branch failure paths own the target fd (structure)
rpc payload facts exit code parses full i32 tokens
utf8 char slice saturates offset plus limit
policy: windows prefix grammar matches backslash descendants and folds deny
policy: windows lexical normalization keeps DOS and UNC roots
policy: windows filePin rel is a real relative path
policy: tail absence walk sees backslash components
policy: exec_start skips the timeout cap
secure: windows path under prefix folds case and backslash boundaries
secure: windows prefix handle is verified before every use (structure)
secure: darwin exe and candidate opens verify fd regularity (structure)
node link deadline math saturates at zero and counts down
node link bufferRecord is bounded by the absolute read deadline
link frame key derivation matches golden HMAC vectors
link frame tag: golden vector and parts streaming agree
link frame tag: tampering, wrong seq and direction are rejected
node link drops an injected REQ frame without a valid tag
node link drops a frame whose payload was flipped after tagging
node link drops a replayed frame with a stale sequence number
node link drops frames that arrive out of order
hub drops an injected RESP frame without a valid tag
tls_server readSome waits for the link writer mutex
tls_server readSome arms the send deadline before reading
tls_server idle readSome leaves the writer mutex free while waiting
tls_server threading install is idempotent under concurrent callers
node link handshake is bounded by one absolute deadline
link frame auth refuses the sequence wraparound at maxInt(u64)
hub probe deadline follows the awake clock
tls_server completes a real handshake and echoes plaintext with the std client
tls_server refill never parses a mid-record continuation as a record header
tls_server segmented read keeps the absolute deadline
tls_server read spans record boundaries without misparsing
tls_server holds a partial next-record header across refills
tls_server handshake completes over a segmented client flight
hub probe budget covers the PING write
hub probe budget bounds the write mutex admission
hub register does not park behind the old link'"'"'s stuck writer
hub handshake writes live inside the handshake budget
tls_server readSome timeout is retryable and hard errors stay sticky
tls_server WANT_READ retries the buffered read before the socket wait (structure)
node link speaks tagged frames through a TLS terminator relay'

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
