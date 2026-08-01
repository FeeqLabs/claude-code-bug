# b-023 — Chain-halt DoS in `repair_oos_accounts` / `repairMissingAccountsBinary`

Found by applying the methodology in `b-023/answers/CLAUDE.md` to
`b-023/source-code/core` (shardeum `shardus-core`). All line numbers below
are verified against the live source in `source-code/core/src` in this
checkout.

## The vulnerable handlers and loop

`src/state-manager/AccountPatcher.ts`, `setupHandlers()`:

- JSON handler: `this.p2p.registerInternal('repair_oos_accounts', ...)`
  — registration at line 336, body 337–487.
- Binary handler: `repairMissingAccountsBinary`, defined 489–643,
  registered via `this.p2p.registerInternalBinary(repairMissingAccountsBinary.name, repairMissingAccountsBinary.handler)`
  at line 694.

Both destructure `receipt2` straight out of the attacker-supplied
`repairInstruction` (no extraction from local trusted state):

```
// line 349 (JSON) / 504 (binary)
const { accountID, txId, hash, accountData, targetNodeId, receipt2 } = repairInstruction
...
// line 384-385 (JSON) / 539-540 (binary)
const bestMessage = receipt2.confirmOrChallenge
const receivedBestVote = receipt2.appliedVote
```

and both then run the identical unbounded loop over it:

```
// AccountPatcher.ts:413-423 (JSON handler)
// AccountPatcher.ts:568-578 (binary handler) — byte-identical logic
for (let i = 0; i < receivedBestVote.account_id.length; i++) {
  if (receivedBestVote.account_id[i] === accountID) {
    if (receivedBestVote.account_state_hash_after[i] !== calculatedAccountHash) {
      ...
    }
    break
  }
}
```

`account_id` is typed `string[]` (`AppliedVoteSerializable` in
`types/AppliedVote.ts:10`), but that is a compile-time-only annotation.
Nowhere between the wire and this loop does either handler call
`Array.isArray(receivedBestVote.account_id)` (confirmed — no
`Array.isArray` appears anywhere in `AccountPatcher.ts`). A plain object
`{ length: N }` passes straight through.

## Attacker payload

```js
{
  repairInstructions: [{
    accountID: '<any address in the target node's storage range>',
    txId: '<txId of a real tx the target node has already archived>',
    hash: '<any value the target's account-hash cache won't already match>',
    accountData: { data: { ...minimal valid WrappedData... }, timestamp: 0 },
    targetNodeId: '<target node's real id>',
    receipt2: {
      confirmOrChallenge: null,
      appliedVote: sign({                 // signed with the attacker's OWN real keypair
        txid: '<same real txId>',
        transaction_result: true,
        node_id: '<attacker's own real node id>',
        account_id: { length: 10000000000000000000000000000000000000000000 }, // > 2^53-1
        account_state_hash_after: [],
        account_state_hash_before: [],
        cant_apply: false,
        app_data_hash: '',
      }),
    },
  }],
}
```

## Why every prior check passes

Walking the checks that run before the loop, in order (JSON handler line
refs; binary handler is the same logic a few lines later):

1. `targetNodeId !== Self.id` (352) — attacker sets this to the real
   target's id, obtained from the public archiver `full-nodelist` /
   each node's `/nodeinfo` endpoint. Not a barrier.
2. `isInStorageGroup` via `getStorageGroupForAccount(accountID)` (358–363)
   — attacker picks any `accountID` string that maps into the target's
   shard range; no ownership of that account required.
3. Account-hash-cache freshness checks (365–373) — trivially satisfied by
   using an `accountID`/`hash` pair the target hasn't cached, or a fresh
   `accountData.timestamp`.
4. `archivedQueueEntry = getQueueEntryArchived(txId, ...)` must be
   non-null (375–381) — the attacker submits (or simply observes) one
   ordinary, otherwise-irrelevant transaction that the target node
   processes and archives, then reuses its real `txId`. Routine, not a
   privilege.
5. `eligibleNodeIdsToVote.has(receivedBestVote.node_id)` (389) — this set
   is computed in `TransactionQueue.ts:2091-2100` as the top-ranked slice
   (at least 3, `Math.max(3, executionGroup.length * voterPercentage)`)
   of the transaction's execution group. The attacker sets `node_id` to
   their **own** real, currently-active node id — any staked node
   routinely lands in this set for transactions that touch its own
   shard, especially a transaction the attacker submitted themselves.
6. **The only real cryptographic gate** — signature check (395–401 / 550–556):
   ```
   this.crypto.verify(receivedBestVote as SignedObject,
     archivedQueueEntry.executionGroupMap.get(receivedBestVote.node_id).publicKey)
   ```
   This proves `receivedBestVote` — whatever shape it has — was signed by
   the real private key belonging to `node_id`. Since the attacker set
   `node_id` to their own node, they legitimately hold that key and can
   sign literally any object, including one with
   `account_id: { length: N }`. `crypto.sign`/`crypto.verify`
   (`src/crypto/index.ts:197-213`) operate on the JSON round-tripped
   object (`Utils.safeJsonParse(Utils.safeStringify(obj))` at line 198)
   and never validate field types or shapes — only that the bytes match
   the claimed signer.
7. `receivedBestVote.transaction_result` truthy (binary path, line 559) —
   attacker sets `true`.

**Net requirement: control one real, currently active/staked validator
node (to self-sign the forged vote) and know one real `txId` the target
node has archived.** No cryptography is broken and no other node's
identity is impersonated — this matches the `report.md` PoC already in
this folder, which signs with one real node's `secrets.json`.

## Why the loop never terminates (not just "very long")

`receivedBestVote.account_id` is a plain object with only a `.length`
property — it has no indexed elements, so `receivedBestVote.account_id[i]`
is `undefined` for every `i`. The comparison
`receivedBestVote.account_id[i] === accountID` is therefore always
`false`, so the loop body never throws and never hits its `break` — it
just runs to the fake bound. Choosing `N` (`10^46` in the payload above,
or anything > `Number.MAX_SAFE_INTEGER` = `2^53-1` =
`9,007,199,254,740,991`) means that once `i` reaches that magnitude,
`i++` becomes a no-op under IEEE-754 double-precision arithmetic — `i`
stops increasing, so `i < N` never becomes false. This is a
mathematically infinite loop, not merely a slow one.

Nothing inside the loop body can throw (it's pure `===` comparisons on
`undefined` and a property read), so the surrounding `try { ... } catch
(e) {}` (JSON handler, 347/482-483) and `try {...} catch (e) {
console.error(...) }` (binary handler, 495/636-638) are irrelevant — they
can only catch synchronous exceptions, and this code path never throws
one.

## Dead validation code (existing schema, never wired up)

A correct ajv schema for this exact request already exists and **is**
registered at process start:

- `src/types/ajv/RepairMissingAccountsReq.ts:12-35` declares
  `schemaAppliedVote` with `account_id: { type: 'array', items: { type: 'string' } }`
  (and the same for `account_state_hash_after`/`_before`) — this would
  correctly reject the forged payload if it ran.
- It's registered under the key `'RepairMissingAccountsReq'`
  (line 101: `addSchema('RepairMissingAccountsReq', schemaRepairMissingAccountsReq)`),
  and `initRepairMissingAccountsReq()` is called from the global ajv
  bootstrap (`types/ajv/Helpers.ts:15,29`), so the schema genuinely
  exists in the running validator's ajv instance.

But every call site that would invoke it against this payload is
commented out, **and** the ones that exist use the wrong registry key:

- `AccountPatcher.ts:502`: `// verifyPayload('RepairOOSAccountsReq', payload)`
- `types/RepairOOSAccountsReq.ts:22-25` and `:69-72`: both
  `verifyPayload('RepairOOSAccountsReq', ...)` calls are commented out
  (with a `//TODO: add file in /ajv folder` note above them).

Note the name mismatch: the commented calls all pass
`'RepairOOSAccountsReq'`, but the schema is registered as
`'RepairMissingAccountsReq'`. `getVerifyFunction()`
(`utils/serialization/SchemaHelpers.ts:31-39`) throws
`Error("error missing schema RepairOOSAccountsReq")` for an unregistered
name — so simply uncommenting these calls without also fixing the key
would throw at request time, and that throw would itself be silently
swallowed by the empty/logging `catch` blocks noted above, leaving the
handler just as exploitable. Both the missing wiring and the key
mismatch need to be fixed together.

## "Binary" protocol, but this one field isn't

`repairMissingAccountsBinary`'s request type, `RepairOOSAccountsReq`
(`types/RepairOOSAccountsReq.ts`), uses real field-by-field binary
reads/writes for `accountID`, `hash`, `txId`, `targetNodeId`
(`stream.writeString`/`readString`) and `accountData`
(`serializeWrappedData`/`deserializeWrappedData`, lines 32-44/55-67).
Only `receipt2` — the field carrying `appliedVote.account_id` — is
serialized via `serializeAppliedReceipt2`/`deserializeAppliedReceipt2`
(`types/AppliedReceipt2.ts`).

That function's *real* implementation is written out field-by-field,
including a call to the properly bounded `serializeAppliedVote`/
`deserializeAppliedVote` (`types/AppliedVote.ts`) — which caps
`account_id.length`/`account_state_hash_after.length` to `UInt16`
(0–65535) via `stream.writeUInt16(obj.account_id.length)` (line 31) and
reconstructs a genuine bounded JS array on read (`readUInt16()` then a
bounded `for` loop, lines 66-71) — but every line of that real
implementation is commented out
(`AppliedReceipt2.ts:35-42` serialize, `52-69` deserialize) and replaced
with:

```js
// serialize (line 43-44)
const stringified = Utils.safeStringify(obj)
stream.writeString(stringified)

// deserialize (line 70-71)
const stringified = stream.readString()
return Utils.safeJsonParse(stringified)
```

So even the "binary" endpoint round-trips `receipt2` (and therefore
`appliedVote.account_id`) through plain `JSON.stringify`/`JSON.parse`,
which preserves `{ length: N }` exactly as given. The bounded array
codec that exists in this same codebase, and is correctly used elsewhere
for `AppliedVote` (e.g. `GetAppliedVoteResp`/`GetAppliedVoteReq` in
`TransactionConsensus.ts`), simply isn't reached for this field. The
"this is a binary/typed protocol" guarantee does not extend past the
outer envelope — `repairMissingAccountsBinary` is exactly as exploitable
as the plain JSON `repair_oos_accounts` handler.

## Blast radius

- `p2p.registerInternal`/`registerInternalBinary` handlers run on
  Node.js's single main thread. The vulnerable loop contains no `await`,
  so once entered it can never yield back to the event loop — it freezes
  *every* other internal handler, external HTTP endpoint, gossip
  handler, and timer (including cycle/consensus ticks) on that process,
  not just processing related to the targeted account or transaction.
- `repair_oos_accounts`/`repairMissingAccountsBinary` are part of core
  `shardus-core` and present identically on every validator node running
  this code. `targetNodeId` is attacker-chosen per message, and active
  nodes' internal addresses are publicly discoverable (archiver
  `full-nodelist`, each node's `/nodeinfo`). One crafted message per
  node — all reusing the same self-signed forged vote and one real,
  already-archived `txId` — freezes each node's event loop
  independently; sent to every active node, this is a simultaneous,
  total network halt (no new transactions can be confirmed), matching
  the impact already documented and PoC'd against a 32-node local
  network in `b-023/report.md` in this same folder.

## Summary

| Check | What it actually verifies | Attacker cost to satisfy |
|---|---|---|
| `targetNodeId === Self.id` | routing | none (public info) |
| storage-group membership | `accountID` routing | none (attacker picks address) |
| hash-cache freshness | staleness | none |
| `archivedQueueEntry` exists | `txId` was really processed | submit one ordinary tx |
| `eligibleNodeIdsToVote.has(node_id)` | `node_id` is a real voter for real `txId` | use attacker's own node id |
| `crypto.verify(vote, pubkey(node_id))` | `vote` bytes signed by `node_id`'s real key | attacker signs with their own real key — proves authorship, not shape |
| `Array.isArray(vote.account_id)` | — | **does not exist on this path** |

The gap is exactly the bug class in `CLAUDE.md`: a field statically typed
`string[]`, authenticated for *authorship* by a real signature, but never
checked for *shape* before its `.length` drives an unbounded, exception-free,
event-loop-blocking loop — reachable by anyone who controls one active
network identity.
