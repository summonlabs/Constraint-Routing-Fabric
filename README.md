# Constraint Routing Fabric

**Constraint Routing Fabric 1.0.0** — the explicit constraint-evaluation and constrained-route-selection
runtime of the Distributed Fabric Infrastructure / Fabric OS stack.

Copyright 2026 Summon Software Labs. Apache License 2.0.

Constraint Routing Fabric (CRF) answers exactly one question, deterministically and with full evidence
binding:

> Given an explicit source, destination, authoritative candidate set, current dependency generations,
> and a declared set of mandatory and preference constraints, which candidates satisfy every mandatory
> requirement, which candidates remain admissible under current authority, what deterministic ordering
> applies among admissible candidates, and exactly why is each candidate accepted, rejected, or reduced
> to revalidation?

It is a library and a coordinator, not a routing protocol implementist. Nothing in this repository
forwards a packet, reserves a byte of bandwidth, discovers a path, or measures a network.

---

## Table of contents

- [What this runtime owns and what it does not](#what-this-runtime-owns-and-what-it-does-not)
- [The boundary with Path Planner, Path Authority and Route Fabric](#the-boundary-with-path-planner-path-authority-and-route-fabric)
- [Hard constraints versus soft preferences](#hard-constraints-versus-soft-preferences)
- [Typed constraints](#typed-constraints)
- [Evidence semantics](#evidence-semantics)
- [Latency: modelled versus measured](#latency-modelled-versus-measured)
- [Bandwidth capability is not a reservation](#bandwidth-capability-is-not-a-reservation)
- [Topology, locality and isolation](#topology-locality-and-isolation)
- [Capability and administrative policy](#capability-and-administrative-policy)
- [Canonicalization, digests and contradictions](#canonicalization-digests-and-contradictions)
- [Evaluation model and outcomes](#evaluation-model-and-outcomes)
- [Deterministic precedence](#deterministic-precedence)
- [Candidate ordering](#candidate-ordering)
- [Currentness, invalidation and watermarks](#currentness-invalidation-and-watermarks)
- [Two-phase evaluation](#two-phase-evaluation)
- [Lifecycle](#lifecycle)
- [Authority, epochs and fencing](#authority-epochs-and-fencing)
- [Persistence and conservative recovery](#persistence-and-conservative-recovery)
- [Distributed protocol](#distributed-protocol)
- [Resource limits](#resource-limits)
- [Explanations](#explanations)
- [Snapshots and diffs](#snapshots-and-diffs)
- [Building](#building)
- [Installing and consuming](#installing-and-consuming)
- [Examples](#examples)
- [Validation](#validation)
- [Validation classes: real, synthetic, unsupported](#validation-classes-real-synthetic-unsupported)
- [Genuine limitations](#genuine-limitations)
- [License](#license)

---

## What this runtime owns and what it does not

CRF **owns**:

- ConstraintSetId, constraint lifecycle, generations, provenance and authority.
- Typed mandatory and preference constraints.
- Deterministic normalization and contradiction detection.
- Evaluation of exact candidate paths against explicit constraints.
- Hard admissibility versus soft preference separation.
- Latency, bandwidth-capability, topology, locality, isolation, capability and policy constraints.
- Exact evidence and generation binding.
- Deterministic rejection precedence and candidate ordering.
- Stale-evaluation fencing and revalidation.
- Snapshots, diffs, explanations and semantic digests.
- Persistence, conservative recovery and distributed publication/evaluation authority.

CRF **does not own**, and never computes, overrides or claims:

| Not owned | Owner |
| --- | --- |
| Identity truth | Identity registry |
| Topology truth, link state, port configuration | Topology and link-state authorities |
| Capability truth | Fabric Capability Registry |
| Failure-domain truth | Failure-domain authority |
| Fabric Epoch issuance | Fabric Epoch issuer |
| Candidate path discovery | Path Planner |
| Path legality | Path Authority |
| Route lifecycle, ECMP, weighting, adaptive routing, convergence | Route Fabric |
| Path diversity and independence guarantees | Path Diversity Fabric |
| Traffic engineering, bandwidth reservation, congestion measurement | The respective fabric components |
| Physical forwarding | The forwarding plane |

The boundary is machine-readable in `include/constraint_routing_fabric/source_of_truth.hpp` and is
asserted by `tests/test_snapshot_protocol.cpp` (`Protocol.BoundaryDeclarationsAreComplete`).

---

## The boundary with Path Planner, Path Authority and Route Fabric

```
Path Planner   -> produces candidates (PathId, node/link sequence, planner rank/cost)
Path Authority -> decides exact path legality at an exact PathAuthorityGeneration
CRF            -> evaluates declared constraints over those exact candidates
Route Fabric   -> owns route state; consumes CRF's immutable evaluation identity
```

- Every candidate carries the **exact** `PathAuthorityGeneration` it was adjudicated at, and an exact
  `PathAuthorityVerdict`. A candidate whose generation is stale is reported `STALE_PATH_AUTHORITY`.
  A candidate Path Authority rejected is reported `UNAUTHORIZED` / `PATH_NOT_LEGAL`; a candidate Path
  Authority did not evaluate is reported `UNKNOWN_REQUIRED_EVIDENCE` /
  `PATH_AUTHORITY_NOT_EVALUATED`. **CRF never overrides Path Authority.**
- CRF does not search the graph. If no candidate passes, the batch reports
  `NO_ADMISSIBLE_CANDIDATE` with the deterministic primary batch reason. It never invents a candidate.
- CRF publishes an immutable `RouteFabricHandoff` (set identity and generation, path identity, Path
  Authority generation, evaluation identity and generation, outcome, evidence binding, semantic digest).
  It never mutates Route Fabric.

The stages below are kept strictly separate, and the API never conflates them:

```
CANDIDATE EXISTS
CANDIDATE IS LEGAL                                    (Path Authority)
REQUIRED EVIDENCE EXISTS                              (UNKNOWN_REQUIRED_EVIDENCE)
MANDATORY CONSTRAINTS PASS                            (HARD_CONSTRAINT_FAILED)
SOFT PREFERENCES PRODUCE ORDER                        (ADMISSIBLE_WITH_PREFERENCES)
ROUTE IS SELECTED                                     (Route Fabric)
ROUTE IS INSTALLED                                    (Route Fabric)
PHYSICAL NETWORK DELIVERS EXPECTED PERFORMANCE        (not claimed anywhere in this repository)
```

---

## Hard constraints versus soft preferences

- `ConstraintScope::Mandatory` constraints decide **admissibility**.
- `ConstraintScope::Preference` constraints may only **rank candidates that are already admissible**.
- A soft preference can never rescue a hard failure. This is a tested property
  (`tests/test_evaluator.cpp`, `tests/test_property.cpp`), not a convention.
- Preference evaluation reuses the mandatory predicate implementation exactly, so a preference can
  never disagree with the hard result it ranks.

---

## Typed constraints

All eighteen kinds are typed, explicitly bounded and versioned. There is no free-form executable policy
language in 1.0.0.

| Kind | Payload | Notes |
| --- | --- | --- |
| `MaxLatency` | integer microseconds + explicit `LatencySource` | modelled and measured latency never mix |
| `MinBandwidthCapability` | integer bits per second | capability evidence, never a reservation |
| `RequiredNode` / `ForbiddenNode` | node identities | conjunction over the listed set |
| `RequiredLink` / `ForbiddenLink` | link identities | conjunction over the listed set |
| `RequiredTier` / `ForbiddenTier` | tier identities | every traversed node is checked |
| `RequiredSite` / `ForbiddenSite` | site identities | every traversed node is checked |
| `LocalityScope` | authoritative `DomainKind` + locality identity | membership only, never a name prefix |
| `IsolationClass` | isolation class identity | requires positive proof for every entity |
| `RequiredCapability` / `ForbiddenCapability` | capability identities | missing evidence is UNKNOWN |
| `RequiredFailureDomainRelation` | domain kind + `Distinct` + minimum count | |
| `ForbiddenFailureDomainRelation` | domain kind + `Shared` or `Distinct` + count | |
| `AdministrativePolicy` | policy identities | exact policy generation binding |
| `MaxHopCount` | integer hops | structural |

Every kind validates its own payload: a `MaxLatency` carrying a node list, a `RequiredNode` carrying a
link list, a zero or negative bound, a mandatory constraint carrying preference metadata, a preference
with weight outside 1..1000, or `PermitUnknownNegative` on a positive requirement are all rejected at
construction time.

---

## Evidence semantics

Every evaluation binds the exact generations it actually used:

```
topology, link_state, capability, failure_domain, policy, planner, path_authority
plus the consulted-family mask and the evidence capture tick
```

- Only the families a constraint set actually consults are bound. A change to a policy generation does
  not invalidate an evaluation that never consulted policy.
- **A missing fact is never inferred from a name.** Locality comes from authoritative
  `LocalityRef` membership; failure domains come from authoritative `FailureDomainRef` membership;
  capabilities come from the Fabric Capability Registry reference set.
- **UNKNOWN required evidence fails closed.** If the authoritative evidence a mandatory constraint
  needs is absent, the result is `UNKNOWN_REQUIRED_EVIDENCE`, never a silent pass. The only relaxation
  is `UnknownPolicy::PermitUnknownNegative`, which may treat missing evidence as satisfying a
  *negative* (forbidden) constraint. It is rejected outright on any positive requirement.
- `EvidenceProvenance` labels every figure. Synthetic fixtures are labelled `SyntheticFixture` and are
  never presented as measurements.

---

## Latency: modelled versus measured

`MaxLatency` binds an explicit `LatencySource`:

- `LatencySource::PlannerCost` consumes the planner's modelled cost and binds the exact
  `PlannerGeneration`.
- `LatencySource::ObservedLatency` consumes an observed figure and binds the exact
  `LinkStateGeneration` that carried the observation.

A candidate carrying only observed latency is `UNKNOWN_REQUIRED_EVIDENCE` /
`LATENCY_EVIDENCE_UNAVAILABLE` against a planner-cost constraint, and vice versa. The candidate's own
latency generation must agree with its evidence binding; a mismatch is malformed input, not a silent
fallback. All latency values are integer microseconds.

---

## Bandwidth capability is not a reservation

`MinBandwidthCapability` compares a declared capability threshold against attested **capability
evidence**, computed as the bottleneck of the per-link attested capability figures at the exact
`CapabilityGeneration` the candidate binds.

Passing it means: *current capability evidence satisfies the declared threshold under the evidence
model*. It does **not** reserve capacity, does **not** deduct from any pool, and does **not** guarantee
delivered throughput. The API, the explanations and the examples say so explicitly. Evaluating the same
candidate twice changes nothing: there is no reservation state to consume.

---

## Topology, locality and isolation

- Topology constraints bind the exact `TopologyGeneration`.
- Locality uses authoritative identities and relationships. Rack, site, zone or plane membership is
  read from an explicit `LocalityRef`; a node identifier that happens to share a prefix with a site
  name is irrelevant.
- Isolation constraints consume authoritative failure-domain evidence. Independence is never claimed
  merely because no common label happened to be found: every traversed entity must carry a positive
  `IsolationAttestation` for the declared class at the required `FailureDomainGeneration`. Absent
  proof is `UNKNOWN_REQUIRED_EVIDENCE`; conflicting proof is a hard failure.
- Failure-domain relations are evaluated over the union of node and link domain sets. Incomplete
  membership is UNKNOWN for positive relations under the default fail-closed policy.

---

## Capability and administrative policy

- Capability constraints bind exact Fabric Capability Registry generations where integrated. Missing
  required capability evidence is UNKNOWN, never SUPPORTED.
- `ForbiddenCapability` under the default `FailClosed` policy is deliberately strict: a missing
  capability record is not proof of absence, so absence is UNKNOWN rather than a pass. Operators whose
  registry provides a complete authoritative enumeration for the bound generation can set
  `PermitUnknownNegative` on the forbidden constraint to obtain the "absence is proof of absence"
  reading. Both readings are exercised by the tests and the examples.
- Administrative policy constraints are typed, bounded, versioned and deterministic: each policy is
  checked against a `PolicyAttestation` carrying an exact `PolicyGeneration`. A policy that is
  attested at a stale generation is UNKNOWN; a policy with no attestation at all is a hard failure.

---

## Canonicalization, digests and contradictions

Canonicalization is deterministic and total:

- Constraint ordering is canonical (payload first, then identity).
- Entity lists are sorted and de-duplicated.
- Equivalent duplicate constraints (identical payload, different identities) collapse to the smaller
  `ConstraintId`, and each collapse is reported as a `SetDefect`.
- Numeric encodings are integer and fixed-point only; there is no floating point anywhere in the
  library.
- Commutative policy content digests identically: equivalent semantic constraint sets produce identical
  digests and identical results regardless of publication or insertion order.

Contradictions are detected **before** evaluation and the set is rejected **atomically** — the caller's
set is left byte-identical:

| Contradiction | Example |
| --- | --- |
| `RequiredAndForbiddenSameEntity` | `RequiredNode X` + `ForbiddenNode X` (also links, tiers, sites, capabilities) |
| `ConflictingLocalityScopes` | two `LocalityScope` of the same domain kind with different domains |
| `ConflictingIsolationClasses` | two different required isolation classes |
| `FailureDomainRelationConflict` | required `Distinct n >= 2` + forbidden `Shared`; required `Distinct k` + forbidden `Distinct m <= k` |
| `ImpossibleHopBudget` | three distinct required nodes with `MaxHopCount 1` |

---

## Evaluation model and outcomes

Each evaluation binds the set identity and generation, the exact `PathId`, the exact
`PathAuthorityGeneration`, the evidence generations actually used, the evaluation generation, the
outcome, one deterministic primary reason, a bounded complete reason vector, the publishing provenance
and a semantic digest.

Outcomes are a closed enumeration, **never a boolean**:

```
ADMISSIBLE
ADMISSIBLE_WITH_PREFERENCES
HARD_CONSTRAINT_FAILED
UNKNOWN_REQUIRED_EVIDENCE
STALE_PATH_AUTHORITY
STALE_CONSTRAINT_SET
STALE_EVIDENCE
REVALIDATION_REQUIRED
UNAUTHORIZED
RESOURCE_LIMIT
MALFORMED
```

---

## Deterministic precedence

One documented precedence, applied in this order:

```
1. resource admission
2. wire / decode
3. caller identity
4. epoch / boot / scope
5. constraint-set lifecycle and generation
6. Path Authority generation and verdict
7. mandatory evidence currentness
8. mandatory constraints, in canonical constraint order
9. preference evaluation
10. deterministic candidate ordering
```

Reasons are totally ordered by `(precedence class, canonical constraint ordinal, reason code, constraint
identity, evidence family, subject, expected, actual)`. A multi-failure input therefore returns the
**same primary reason independent of container order**, and the primary reason is always the first
element of the canonical reason vector.

Resource admission precedes wire decode because a frame that cannot be admitted is never decoded; this
is the only deviation from the ordering printed in the specification and it is deliberate.

---

## Candidate ordering

Ordering uses explicit policy only, in this precedence:

```
1. hard admissibility
2. preference vector (lexicographic over canonical preference slots)
3. planner rank              -- only when RankingPolicy::consume_planner_rank is set
4. planner cost              -- only when RankingPolicy::consume_planner_cost is set,
                                and only against the declared expected cost model
5. documented tie-break      -- PathId ascending, or node-sequence lexicographic
```

Arrival order, unordered-container iteration order and opaque hashes are never used as hidden
tie-breaks. The batch canonicalizes the candidate population by identity before evaluation, so a caller
cannot observe its own container order. A candidate whose declared cost model differs from the policy's
expected model is reported `PLANNER_COST_MODEL_MISMATCH` rather than silently mixed.

---

## Currentness, invalidation and watermarks

- Every evaluation binds only the evidence it actually used.
- A reverse index maps dependency keys (constraint set, path, node, link, capability, policy, failure
  domain, locality domain, isolation class, planner, topology, link state, path authority) to the
  evaluations that used them.
- Monotonic invalidation watermarks advance per family and per key. Generations never decrease and never
  wrap.
- **A single capability change does not globally invalidate unrelated evaluations.** Only evaluations
  that bound the changed key are reduced to `REVALIDATION_REQUIRED`; the rest stay current. This is
  tested directly (`tests/test_race.cpp`).
- Mandatory races are closed: an evaluation that begins at capability generation 10 and finishes after
  the coordinator advanced to 11 cannot become current. The equivalent race is proven for Path
  Authority, topology, link state, failure domain and policy, and for lifecycle changes.

---

## Two-phase evaluation

```
snapshot dependencies (under the coordinator lock)
  -> release the lock
  -> evaluate (pure, no locks, no I/O)
  -> reacquire the lock
  -> verify every consulted generation and watermark
  -> commit atomically, or leave no authoritative mutation at all
```

A stale completion leaves **nothing** behind: no evaluation record, no current-result index entry, no
durable write. The observation is returned to the caller with the records marked `StaleAtCommit` and a
deterministic `rejection_reason`. Races are driven in tests by an explicit phase hook, never by a sleep.

---

## Lifecycle

```
DECLARED --Activate--> ACTIVE
ACTIVE --Suspend--> SUSPENDED --Resume--> ACTIVE
ACTIVE --RequireRevalidation--> REVALIDATION_REQUIRED --Revalidated--> ACTIVE
(any non-terminal) --Revoke--> REVOKED --Reinstate--> REVALIDATION_REQUIRED
(any non-terminal) --Supersede--> SUPERSEDED
(any non-terminal) --Retire--> RETIRED   (terminal)
```

Every one of the 63 `(state, event)` pairs is defined and asserted against an explicit oracle table.
Only `ACTIVE` admits an `ADMISSIBLE` outcome; every other state is reported explicitly and never
silently ignored.

---

## Authority, epochs and fencing

- **Default deny.** An empty scope mask authorizes nothing. An incomplete authority context authorizes
  nothing. Being connected is not being authorized. Being a known publisher is not being authorized.
  Durable state is not live authority.
- Registration is default-deny against an out-of-band grant list (`CoordinatorConfig::grants`).
  **No cryptographic authentication is provided in 1.0.0**; the grant list is the entire authorization
  surface and the transport is unauthenticated loopback.
- Every mutation and publication binds `CoordinatorEpoch`, `PublisherId`, `WorkerBootId`, scope,
  expected generation and `MutationAttemptId`.
- **Exact replay is idempotent and advances nothing.** Attempt-identity reuse with a different payload
  is rejected as `MutationAttemptConflict`.
- A fresh process gets a fresh `WorkerBootId`; the previous boot is fenced permanently. Fenced boots
  can never register again, in this or any later epoch.
- Coordinator epochs are strictly monotonic. A restart advances the epoch, restores **no** live
  publisher authority, and fences every boot that held live authority in the previous incarnation. A
  worker from a previous coordinator process cannot re-register even though it can learn the new epoch.
- A durable store is owned by exactly one open coordinator at a time; a second owner is refused. The
  ownership handle is released by the operating system if the owner is killed, so a hard kill never
  leaves a store permanently locked.

---

## Persistence and conservative recovery

- Versioned, bounded, deterministic state in an envelope with a magic prefix, an explicit format
  version, a declared length, a CRC-32C and a SHA-256, written to a temporary file, flushed to stable
  storage, then atomically renamed over the target.
- **A request that requires durability is never acknowledged before the durable write succeeded.** If
  the write fails, the in-memory state is not advanced either.
- Recovery is conservative: constraint definitions, candidate populations, evidence generations and
  watermarks are restored; **no result is restored as current**. Every restored result is
  `RecoveredUnproven` until it is re-proven against current Path Authority and evidence.
- A store that exists but does not describe a valid state is not silently replaced: the unreadable
  bytes are preserved as a quarantine copy.
- Persisted state is validated on the way in and on the way out. Rejected: duplicate constraint
  identity, dangling evidence binding, unknown constraint kind, invalid numeric bound, impossible
  generation, contradictory normalized representation, duplicate evaluation identity, duplicate
  current result, malformed or non-canonical reason vectors, bad magic or version, truncation, bit
  corruption, absurd counts, overflow and trailing bytes.

---

## Distributed protocol

- Explicit protocol version and stable numeric message identifiers; raw C++ layouts are never
  serialized.
- Fixed semantic header (magic, version, message, flags, payload length, epoch, publisher, worker boot,
  mutation attempt, request identity, scopes) plus payload, with a CRC-32C and a SHA-256 computed over
  the semantic header **and** the payload.
- Malformed enumerations, trailing bytes, stale epochs, stale boots and oversized vectors are rejected.
  Every count read from the wire is bounds-checked against the limit that governs its own collection.
- `FrameAssembler` reassembles fragmented reads with a hard bound on started-frame bytes and a hard
  bound on a single frame, so a partial peer cannot pin memory: it fails closed instead of growing
  without limit.
- The coordinator server handles one bounded session per connection and fences the session's boot when
  the connection is lost.

---

## Resource limits

Every bound in `crf::Limits` has a real enforcement site and a test that makes it bite:
`max_constraint_sets`, `max_constraints_per_set`, `max_entity_refs_per_constraint`,
`max_failed_constraints_per_evaluation`, `max_candidates_per_evaluation`, `max_nodes_per_candidate`,
`max_links_per_candidate`, `max_capabilities_per_entity`, `max_domains_per_entity`,
`max_localities_per_entity`, `max_policies_per_candidate`, `max_explanation_reasons`,
`max_batch_size`, `max_publishers`, `max_sessions`, `max_frame_bytes`,
`max_frame_assembly_bytes`, `max_persistence_record_bytes`, `max_evaluations_retained`,
`max_fenced_boots`, `max_mutation_attempts`, `max_name_bytes`, `max_detail_bytes`,
`max_decoded_count`.

Bounds that had no enforcement site were removed rather than left dead; an inventory test asserts that
no declared bound is unconsulted.

---

## Explanations

Operators can ask, for any candidate:

- the deterministic primary reason;
- the complete bounded reason vector, each entry naming the exact constraint identity, constraint kind,
  canonical ordinal, evidence family, typed subject and the expected/actual values;
- the exact evidence generations that were used;
- the currentness cause and the precise invalidation that reduced a result to revalidation.

`crf::describe(reason)` renders a stable, machine-readable line. The primary reason is always the head
of the canonical vector, so explanation truncation can never change the outcome.

---

## Snapshots and diffs

- `DefinitionsSnapshot` and `ResultsSnapshot` are immutable, deterministic and identity-stable:
  equivalent definitions share a snapshot identity, and entry order never affects the digest.
- `diff_constraint_sets` reports constraint addition, removal and change, evidence-requirement changes,
  ranking-policy changes and lifecycle changes.
- `diff_results` reports candidate appearance, disappearance, outcome change, reason change,
  currentness change, authority-generation change and evidence-digest change.
- `diff_evidence_requirements` reports evidence generation movement per family.
- Semantic digests exclude timestamps, memory addresses, sockets, thread identities, arrival order and
  diagnostic counters. Equivalent semantics reached through a different publication order digest
  identically.

---

## Building

Requirements: CMake 3.25 or newer, a C++20 compiler, and (on Windows) the MSVC x64 toolset.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `CRF_BUILD_TESTS` | ON | build the validation suites |
| `CRF_BUILD_EXAMPLES` | ON | build the public-API examples |
| `CRF_BUILD_BENCHMARKS` | ON | build the scale benchmarks |
| `CRF_BUILD_HOST` | ON | build the process-host executable used by the real-process proofs |
| `CRF_ENABLE_ASAN` | OFF | instrument with the MSVC x64 AddressSanitizer |
| `CRF_ASAN_RUNTIME_DIR` | empty | directory holding the MSVC ASan runtime libraries, when the selected toolset does not ship them |
| `CRF_ENABLE_ANALYZE` | OFF | enable the MSVC static analyzer (`/analyze`) |
| `CRF_WARNINGS_AS_ERRORS` | ON | treat first-party warnings as errors |
| `CRF_REGISTER_CTEST` | OFF | register the suite with CTest |

The first-party warning profile is `/W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor` plus the
recommended level-4 extension set (`/w14242 /w14254 /w14263 /w14265 /w14287 /w14296 /w14311 /w14545
/w14546 /w14547 /w14548 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928`) and `/WX`. The test target
additionally silences `C4389` and `C4805` because its assertions deliberately compare integers of
different widths and signedness.

Validation is run by executing the test binaries directly. No timeout is set for any test or validation
command anywhere in this repository: a hanging test is a defect, not something to be timed out. The
`crf_tests` runner prints one line per case and a summary, and exits non-zero when any assertion fails.
CTest registration is available but off by default because CTest imposes a default test timeout.

---

## Installing and consuming

```
cmake --install build --prefix <prefix>
```

The install exports a CMake package:

```cmake
find_package(ConstraintRoutingFabric CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::ConstraintRoutingFabric)
```

The package installs headers, the built library and the CMake package files only. No source tree, no
build tree and no test fixture is referenced by the installed package.

### AddressSanitizer note

The MSVC AddressSanitizer runtime is not installed beside every Visual Studio toolset. When the
selected toolset does not carry `clang_rt.asan_dynamic-x86_64.lib`, configure with
`-DCRF_ASAN_RUNTIME_DIR=<toolset>/lib/x64` and put the matching `bin/Hostx64/x64` directory on
`PATH` so the runtime DLL resolves. This is a toolchain provisioning detail, not a library
limitation: once the runtime is reachable, instrumentation is proven by
`crf_asan_probe`, which contains a deliberate heap overflow and must abort with a report.

---

## Examples

`crf_examples` runs ten scenarios against the public API:

| Scenario | Demonstrates |
| --- | --- |
| `latency_bound` | modelled latency inside/outside the bound, and that observed latency is never mixed in |
| `bandwidth_capability` | capability evidence versus reservation, and unavailable capability evidence |
| `forbidden_topology_entity` | a hard exclusion that no preference can rescue |
| `locality` | authoritative locality membership, mismatch and missing membership |
| `capability_requirement` | required, missing and forbidden capability evidence |
| `policy_constraint` | exact policy generation binding and stale policy attestation |
| `contradictory_constraint_rejection` | atomic rejection of a contradictory set |
| `stale_evidence` | the same candidate at two capability generations |
| `worker_reincarnation` | a fenced boot stays fenced; a fresh boot re-registers |
| `coordinator_restart` | epoch advance, definition survival and conservative recovery |

Run `crf_examples` with no argument to run all of them, or with a scenario name to run one.

`crf_bench` reports scale measurements for canonicalization, evaluation, ordering, digests,
persistence and contradiction scanning, plus a determinism check.

---

## Validation

`crf_tests` contains the validation suites. Every suite is deterministic, uses fixed seeds, and prints
the failing seed on any property violation.

| Suite | What it proves |
| --- | --- |
| `ModelCanonical` | typed constraint validation, canonicalization, contradiction rejection, the exhaustive 63-pair lifecycle table, digest stability |
| `Limits` | every configured bound actually bites; no bound is dead |
| `Evaluator` | outcome classes, per-family staleness, every constraint kind, precedence, truncation |
| `Oracle` | an independent bounded oracle agrees exactly on admissibility, primary reason, reason set and ordering across randomized populations; plus the explicit proofs for forbidden-entity permutations, unknown latency evidence, bandwidth capability versus reservation, locality semantics and contradiction rejection |
| `Property` | hard failure can never be overridden; admissible implies every mandatory constraint passed; stale Path Authority is never admissible; missing required evidence never passes; equivalent insertion order gives identical results; contradictions reject; stale contexts cannot mutate; exact replay advances nothing; generations never decrease or wrap; indexes match records; persistence round-trips |
| `Race` | the two-phase commit closes the capability, topology, policy, failure-domain, Path Authority and lifecycle races; precise invalidation; revalidation restores currentness |
| `Authority` | default deny, scope enforcement, epoch monotonicity, boot fencing, worker reincarnation, replay semantics, durable-state-is-not-authority |
| `Persistence` | envelope integrity, atomic replacement, the durability barrier, quarantine of unreadable stores, adversarial semantic states, byte-level decoder corruption |
| `Process` | **real OS processes**: a killed worker is detected and its boot is fenced; a killed coordinator restarts at a higher epoch, preserves definitions, restores no current results, fences the previous boot and re-proves results |
| `Snapshot` / `Protocol` | snapshot determinism, every diff class, frame round trips, fragmentation, protocol abuse rejection, a full loopback coordinator/client exchange, and the boundary declarations |

---

## Validation classes: real, synthetic, unsupported

**REAL** (actually exercised in this repository):

- Real operating-system processes: `crf_host` coordinators and workers are started, killed with
  `TerminateProcess`, restarted, and their behaviour is asserted from their own output.
- Real loopback TCP transport with the real frame codec and real session handling.
- Real durable files on disk, including atomic replacement, real flush-to-storage, real corruption and
  real quarantine.
- Real MSVC compilation at `/W4 /WX /permissive-`, real `/analyze` runs, and real AddressSanitizer
  instrumentation where the toolchain supports it.
- The independent oracle is a genuinely separate implementation of the documented specification.

**SYNTHETIC** (fabricated, and labelled as such in the code and in every output):

- Topologies, candidate populations, capability figures, latency figures, failure domains, policy
  attestations and isolation proofs used by the tests, examples and benchmarks. Every synthetic figure
  carries `EvidenceProvenance::SyntheticFixture` or an equivalent declaration.

**UNSUPPORTED** (not implemented, not claimed, not proven):

- Physical forwarding, and therefore any claim about delivered throughput or measured network
  performance.
- Bandwidth reservation of any kind.
- Multi-host or multi-datacenter fabric proof. Everything here runs on one host.
- Vendor integrations. None are exercised.
- Cryptographic authentication, confidentiality or authorization of peers.
- Path discovery, path legality, path diversity, traffic engineering, adaptive routing or convergence.
- Consensus. The coordinator is a single authority; there is no replicated state machine.

Synthetic evidence is never turned into a physical-network claim anywhere in this repository.

---

## Genuine limitations

1. **Unvalidated platforms.** Every result in this repository was produced on Windows x64 with MSVC
   19.44. The code contains portable POSIX paths (durable writes, advisory locking, sockets) but they
   were not compiled or executed here. Do not read "vendor-neutral" as "validated everywhere".
2. **Unauthenticated transport.** The distributed protocol provides integrity against accidental
   corruption, not authenticity. Any peer that can reach the loopback port and present a granted
   publisher identity can publish. The grant list is out-of-band provisioning, not authentication.
3. **Single-writer durability.** One coordinator owns one store. There is no replication, no quorum and
   no failover: a coordinator restart is a new epoch over the same bytes.
4. **Bounded mutation de-duplication window.** Idempotency of an exact replay is guaranteed within the
   retained attempt window (`max_mutation_attempts`). An attempt evicted from the window is treated as
   fresh again.
5. **Conservative recovery discards currentness by design.** After a restart nothing is current until it
   is re-proven. That is safe, and it is also work: a large population must be revalidated.
6. **Reduced reason vectors.** The reason vector is bounded twice (distinct failed constraints and total
   reasons). Reasons beyond the bound are dropped and the record sets `reasons_truncated`; the primary
   reason is always retained.
7. **`ForbiddenCapability` under fail-closed is intentionally unsatisfiable without complete
   enumeration.** See the capability section above. This is a semantic choice, documented and tested,
   with an explicit opt-out.
8. **No deadline or cancellation model.** An evaluation runs to completion; there is no partial result
   and no cancellation token.
9. **Snapshots are computed, not retained.** There is no snapshot history and therefore no retention
   bound.
10. **Integer-only semantics.** Latency is microseconds, bandwidth is bits per second and costs are
    fixed-point integers. There is no floating-point model, and therefore no fractional-cost
    expressiveness beyond the declared units.

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
