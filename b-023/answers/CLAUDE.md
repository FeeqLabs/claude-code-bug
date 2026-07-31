# CLAUDE.md — Finding "Trusted `.length` on an Unvalidated Attacker-Controlled Object" DoS Bugs

Methodology for finding this bug class — a request/message handler
that pulls a nested field out of attacker- or peer-controlled input (a
vote, a receipt, a claim, a batch, any structure a static type declares as
`SomeType[]`), and then does `for (let i = 0; i < thatField.length; i++)`
or an equivalent count-driven loop **without ever checking that the field
is actually an array at runtime**. Because the static type is erased at
runtime (TypeScript, or any language where the wire format is
untyped/loosely-typed JSON, msgpack-without-schema, etc.), an attacker can
substitute any object exposing a numeric `.length` (or count) property —
most damagingly a plain object literal like `{ length: 1e46 }` — and the
loop bound becomes an arbitrary, attacker-chosen number, unconstrained by
any array's actual size. This is not shardeum-specific: it applies to any
service (P2P/gossip handler, RPC server, queue consumer, indexer) that
deserializes a message into a typed object and trusts a nested field's
shape without validating it.

## Threat model (frame this before reading code)

- **Where it lives:** internal/peer-to-peer protocol handlers and RPC
  endpoints are the highest-value targets, *more* than public HTTP APIs —
  peer/internal messages are often assumed to be "trusted" (because the
  sender needed some credential to speak on that channel at all) and so
  get **less** input validation than public-facing endpoints, even though
  in a permissionless network "needed a credential" can mean "staked once."
  Look first at handlers registered via internal/gossip/consensus message
  routers, not just `app.get`/`app.post`.
- **Why it's high severity, not just a local bug:** like any runaway loop,
  this doesn't throw, doesn't time out server-side, and doesn't free the
  CPU it's pinned to (see the sibling bug class in
  `bugs/b-022/answers/CLAUDE.md` for the mechanics of why float-precision
  loss can make an "very large" loop bound truly infinite once the loop
  variable passes the language's exact-integer boundary). It's invisible
  to error-rate monitoring.
- **Who can trigger it:** determine what's actually required to reach the
  handler — is it open internal-protocol traffic, or does it require a
  valid signature from a recognized peer/node identity? A signature
  requirement narrows "anyone on the internet" to "anyone who can obtain
  one valid identity in the system" (e.g. stake once, register once) —
  still a real, often permissionless, bar. State precisely what credential
  is required, don't assume "it's an internal endpoint" means "it's safe."
- **Why static types don't save you:** a TypeScript (or similar) type
  annotation like `account_id: string[]` is a compile-time-only promise.
  It constrains code the *author* writes against that variable; it does
  nothing to the actual runtime value produced by
  `JSON.parse`/deserialization of attacker-supplied bytes. Every boundary
  where external bytes become an in-memory object is a place this promise
  can be broken, and the break is invisible unless you check the
  deserializer, not the type declaration.

## Step 1 — Inventory handlers that deserialize peer/attacker-controlled objects

```
# find internal/P2P/message handler registrations (adapt to the framework:
# registerInternal, registerInternalBinary, on('message'), consumer.on, grpc service impl, etc.)
grep -rniE "register(Internal|External)(Get|Post|Binary)?|\.on\(['\"](message|data)['\"]|handleMessage|onMessage" \
  --include=*.ts --include=*.js --include=*.go --include=*.rs --include=*.py .

# find deserialization entry points specifically (these are where type erasure happens)
grep -rniE "JSON\.parse|safeJsonParse|deserialize[A-Za-z]*\(|\.decode\(|protobuf|msgpack" \
  --include=*.ts --include=*.js --include=*.go --include=*.rs --include=*.py .
```

Build a list of every handler that receives a payload containing nested
objects/arrays (votes, receipts, batches, claims, proofs, lists of IDs) —
not just top-level scalar params. This bug class needs a *nested* field,
so flat-parameter endpoints (like b-022's `fromBlock`/`toBlock`) are the
wrong shape; look one level deeper into the payload structure.

## Step 2 — For each hit, find where a nested field's `.length`/count feeds a loop

```
grep -n "for\s*(.*=.*;.*<.*\.length\s*;.*++" <file>     # the classic shape
grep -n "\.length\s*;" <file>                            # broader net, then filter
grep -n "Array\.from({length" <file>
grep -n "new Array(" <file>
```

For every match, trace the object whose `.length` is being read back to
its origin. Ask: **is this object guaranteed by a runtime check (not just
a type annotation) to actually be an array, or could it be any object an
attacker constructed?** If the field came directly off a deserialized
request/message with no `Array.isArray()` (or equivalent) check anywhere
between the wire and the loop, it's a candidate.

## Step 3 — Audit the deserialization path for these specific failure modes

1. **Type erasure at the JSON boundary.** `JSON.parse(untrustedString)`
   (or any dynamically-typed deserializer) returns whatever shape the
   bytes describe — a TS/Go/Rust struct type on the receiving variable is
   not enforced by the parser itself. Confirm there's an explicit runtime
   shape check (`Array.isArray`, a schema validator, a manual field-by-
   field walk) between the parse and first use, not just a type cast
   (`as SomeType`, which is a no-op at runtime in TypeScript).

2. **Schema/validation code that exists but is dead.** Search for
   validation library calls (`ajv`, `zod`, `joi`, `yup`, `protobuf`
   schema files, JSON Schema) related to the message type, then check
   whether the call site that would invoke them against *this* payload is
   actually reached — commented out, behind a flag that's off by default,
   or simply never called on this code path even though the schema is
   defined and registered elsewhere in the codebase. A schema existing in
   the repo is not evidence it runs.
   ```
   grep -rn "verifyPayload\|\.validate(\|ajv\.\|schema\." --include=*.ts --include=*.js .
   ```
   For every hit, check: is the call commented out? Does the *name/key*
   passed to the validator actually match how the schema was registered
   (a string-keyed schema registry silently no-ops or throws on a
   mismatched name — check both directions)?

3. **"Binary"/structured formats that secretly fall back to loose
   JSON for a sub-field.** A message format can have a real, bounded
   binary codec for a type (e.g. a length-prefixed array read with a
   fixed-width integer, capping array size to that integer's max) while a
   *wrapping* struct serializes that same field by just
   `JSON.stringify`-ing the whole sub-object and writing it as a string —
   bypassing the bounded codec entirely for anything nested inside. When
   auditing a "binary"/"typed" protocol, don't assume every field within
   it got the same treatment; check each field's actual
   serialize/deserialize function body, because "this protocol is
   binary/typed" is a property of the outer envelope, not a guarantee
   that propagates to every nested value.
   ```
   grep -n "safeStringify\|JSON\.stringify\|writeString.*JSON\|stringify(obj)" <serializer-file>
   ```
   If you find a nested field being serialized via a plain
   stringify-then-writeString (instead of the field-by-field binary
   writes used for its siblings), that field has none of the format's
   structural guarantees — treat it as equivalent to an unauthenticated
   JSON endpoint for validation purposes.

## Step 4 — Check the specific numeric edge case: `.length` as a forgeable property, not a real array size

Unlike a range-pair bug (two numeric params clamped independently), this
bug class's dangerous input is a **single crafted object**, not a number.
Test/trace what happens when the "array" field is replaced with:
- A plain object literal exposing only `{ length: N }` for some huge `N`
  (no actual indexed elements — `arr[i]` is `undefined` for all `i`,
  which usually just makes every loop-body comparison false rather than
  throwing, so the loop runs to completion of the fake bound rather than
  erroring out early).
- `N` chosen beyond `Number.MAX_SAFE_INTEGER` (JS) or the language's
  equivalent exact-integer limit — as in `bugs/b-022/answers/CLAUDE.md`
  Step 4, once the loop index's magnitude exceeds the precision boundary,
  `i++` can become a no-op, turning "extremely long loop" into
  "mathematically infinite loop."
- `N` as a string, a negative number, `Infinity`, or `NaN` coerced into
  the comparison — confirm the loop condition actually stops rather than
  running zero times or throwing somewhere that's silently caught.

## Step 5 — Confirm real-world reachability

- Identify every check that runs *before* the vulnerable loop in the
  handler (signature verification, membership/eligibility checks, replay
  checks) and determine which of them an attacker can actually satisfy.
  A handler "protected" by a signature check is still vulnerable if the
  attacker can obtain a single valid signing identity (e.g. by staking
  once, registering once) — state precisely what's required, don't treat
  "there's a signature check" as "this is unreachable."
- Check whether any `try { ... } catch { }` wrapping the handler is
  relevant: an infinite/hung loop never throws, so an empty or logging
  `catch` block gives a false sense of safety — it will never fire for
  this bug, only for unrelated errors.
- Determine whether the handling process is single-threaded/event-loop
  based (Node.js, single-threaded async runtimes) — if so, one hung
  request blocks *every other* message that process handles, not just
  the attacker's own.

## Step 6 — Assess blast radius

- Is the vulnerable handler present on every node running this code
  (every validator/peer), or only a subset (indexers, gateways)? A
  message that can be sent to any node running the software, sent to all
  of them, is a network-wide-shutdown claim, not a single-node claim —
  say so explicitly if the code confirms it.
- Does the frozen process share responsibility with consensus- or
  liveness-critical work (block production, vote gossip, leader
  election)? If the code doesn't make this clear, say the impact is
  "this process's availability" rather than asserting "network halt"
  without evidence.

## Guiding principle

For every handler that deserializes a nested "array-shaped" field from
attacker/peer input, ask: **"if I replace this field with a plain object
that only defines `.length`, does anything before the loop actually
reject it — or does a type annotation just make me assume it does?"**
Then walk the literal deserialization call chain for that field end to
end: does it hit a real `Array.isArray` / schema check, or does it fall
through a `JSON.parse`, a stringify/parse shortcut inside an otherwise
strongly-typed binary format, or a validator that's defined but never
actually invoked on this path? The bug survives review specifically
because skimming a type declaration ("it's typed as `string[]`, so it's
fine") is mistaken for a runtime guarantee — the fix is to trace bytes to
first-use for the exact field the loop depends on, not to trust the
nearest type annotation.

## Reporting checklist

- Cite the exact handler(s) and line(s) of the vulnerable loop, and the
  exact deserialization path the malicious field travels before reaching
  it.
- Give a concrete attacker-supplied payload (the malicious field's exact
  shape) and show, step by step, why it passes every check that runs
  before the loop.
- If validation code (schema, `Array.isArray`, etc.) exists in the
  codebase for this exact type, state explicitly whether it's wired into
  this call path or dead code — this is often the single most important
  fact distinguishing "needs a new check" from "an existing check just
  needs to be connected/fixed."
- If the protocol claims to be a strongly-typed/binary format, verify
  field-by-field whether the specific vulnerable field actually uses that
  format's structured codec or silently falls back to loose
  stringify/parse — don't extend the envelope's guarantee to every field
  inside it without checking.
- Explain precisely why the loop doesn't terminate in reasonable time
  (iteration count, and/or language-specific float/integer precision
  loss), not just "a large loop."
- State what authentication/signature/eligibility gate the handler
  actually enforces, and what an attacker needs to satisfy it (e.g. "any
  staked/registered peer," not just "requires a signature").
- State blast radius: per-process impact vs. network-wide if the same
  message is replayed against every node, and whether the frozen process
  shares scope with consensus/liveness-critical work.
- Save analysis under `bugs/<id>/answers/`.
