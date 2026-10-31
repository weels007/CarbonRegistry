# CarbonRegistry — Verified Carbon Credit Registry with a Serial Ledger

> **A project registers its methodology, an annual issuance cap and a beneficiary.** Evidence of real emission reductions is submitted and checked under consensus: the LLM extracts the *reported quantity* from the retrieved document, and the contract issues that amount as a uniquely serialised credit lot. Credits can be transferred, settled (the payment flows to the project beneficiary) or retired — each serial exactly once, so a credit can never be double-spent.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-30%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Why this design](#why-this-design)
- [Consensus design](#consensus-design)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. **Register a project** — `register_project(name, methodology, beneficiary, annual_cap, unit, source_key)`. The cap and the quantity unit are declared once; the beneficiary is the party that receives settlement payments; the `source_key` is a unique string that must appear in the project's own evidence document (e.g. a World Bank indicator code), binding evidence to the project.
2. **Submit evidence** — the beneficiary submits a monitoring report URL plus an EIP-191 signature bound to `{project_id}:{url}:{description}`.
3. **Verify** — anyone calls `verify_evidence`. Validators fetch the report, check that the document contains the project's `source_key` (deterministic, identical on every validator), and the LLM extracts the reported quantity; consensus binds the exact quantity that will be minted.
4. **Issue** — the verified quantity is issued as a credit lot with a unique serial (`VCS-{project}-{n}`), clamped to the project's remaining annual cap. A lot is a *lot*, not a token: it carries the verified tonnage.
5. **Use the credit** —
   - `transfer_credit(serial, to)` — moves the lot to a new owner;
   - `settle_credit(serial, buyer)` — the buyer pays; the value is **escrowed** by the registry, and `release_settlement(serial)` pays it to the project beneficiary and hands the lot to the buyer;
   - `retire_credit(serial, note)` — burns the lot against a compliance claim; retired is final.
6. **Cancel a stuck settlement** — `cancel_settlement(serial)` returns the escrowed value to the seller after the settlement window, so a buyer can never lose money to a payout that never happened.

```
register_project ──► submit_evidence ──► verify_evidence ──► lot issued
                                                             │
                        ┌────────────────────────────────────┼─────────────────────────┐
                        │                                    │                         │
                 transfer_credit                   settle_credit (payable)        retire_credit
                        │                                    │                         │
                  new owner                    ┌───────────────┴────────────┐   retired (final)
                                               │                            │
                                          release_settlement        cancel_settlement
                                               │                            │
                                     paid to beneficiary            refunded to seller
```

---

## Why this design

Carbon registries are *ledgers*, and this contract is built like one rather than like a token contract:

- **Credits are serials with one owner and one terminal state.** Double-spending is not prevented by accounting conventions — it is prevented by explicit state transitions (`issued → settling → settled`, `issued → retired`, `issued → issued` with a new owner). A retired or settled serial can never be spent again.
- **The model extracts a quantity, it does not judge.** It reads the amount the report states; the number of credits issued is derived on-chain from that number and clamped to the registered cap. No score decides value, and no model computes a price — and what consensus accepts is the literal minted amount, not a range.
- **The evidence must be about this project.** Each project registers a `source_key` (e.g. its registry serial or a statistical indicator code); verification fails unless the fetched document contains that key, so a report describing a different project cannot mint credits here. The check is a deterministic substring test, identical on every validator.
- **The unit is declared on-chain.** Each project records the unit its reports use (`t CO2e`, `Mt CO2e`), so the ledger is self-describing and the cap and the quantities are always in the same unit.
- **Evidence sources are submitter-independent.** A project cannot present a page it controls; only registries and public statistical agencies are fetchable, and the source is resolved over DNS-over-HTTPS before and after every request.
- **Settlement is two-step on purpose.** The buyer's payment is held by the registry and only reaches the beneficiary on an explicit release; if that never happens, the seller can cancel and get the money back. A credit can therefore never be paid twice *and* a buyer can never be stuck.
- **Periodic reporting.** A project may submit a new monitoring period and receive additional lots until its annual cap is reached — issuance stops at the cap, not at the first report.

---

## Consensus design

`verify_evidence` uses `run_nondet_unsafe` with the Equivalence Principle:

- **Leader**: fetches the evidence through the trusted fetch path, checks the document contains the project's `source_key`, and asks the LLM for the reported amount in integer thousandths (the calldata layer cannot encode floats). The returned value is the **exact clamped issuance** — canonicalized to a 0.1-unit grid and clamped to the remaining annual cap — i.e. the literal number of milli-units that will be minted.
- **Validator**: independently fetches, runs the same deterministic `source_key` substring check on the body (case-insensitive `in` — identical arithmetic on every validator, never an LLM boolean), extracts its own quantity, and accepts **iff** its own clamped issuance equals the leader's exactly. No ±% band exists: the accepted value *is* the minted value.
- **Attribution is deterministic**: the `source_key` check ensures the fetched document is about the registered project (a report for a different project/indicator fails the check and cannot mint credits for this one). The LLM's role stays purely numeric extraction.
- **Error classification**: `[EXPECTED]` and `[EXTERNAL]` (source unreachable, 4xx, blocked host) must match exactly; `[TRANSIENT]` (5xx/network) agrees if both fail; `[LLM]` always disagrees, forcing rotation.
- **Permanent vs transient**: a permanent evidence failure is *recorded* (`status = evidence_failed`, `failure_reason`) instead of reverting, so the project can resubmit; a transient failure reverts and changes nothing.

---

## Reusable patterns

- **Quantity extraction**: LLM returns an integer in thousandths of the source's unit, with a whole-unit fallback.
- **Serial ledger**: unique serials, single owner, explicit terminal states, and per-lot settlement fields — double-spend protection by construction.
- **Escrowed settlement with timeout refund**: hold → release, or cancel-and-refund after the window — a payment can never be lost or paid twice.
- **Periodic issuance with an annual cap**: `issued_milli` vs `annual_cap_milli`; verification clamps instead of over-issuing.
- **Trusted fetch path**: submitter-independent domain allowlist, DoH resolution per hop, post-fetch re-resolution requiring an unchanged and still-public address set (IP pinning is impossible on-chain — the validator rejects IP literals with `TLD_FORBIDDEN`, measured on studionet).
- **Address coercion** for client-supplied addresses, and `EthSend` payouts (`on="finalized"`).

---

## Security & audit

- **Evidence authenticity**: `submit_evidence` requires an EIP-191 signature over `{project_id}:{url}:{description}` whose recovered signer equals the transaction sender, and the sender must be the project's beneficiary.
- **Evidence attribution**: the fetched document must contain the project's registered `source_key` (case-insensitive substring); a document about a different project cannot mint credits for this one, and the check is deterministic — not an LLM judgement.
- **Source trust**: only allowlisted, submitter-independent domains may be fetched; every hop is resolved over DNS-over-HTTPS before the request (private/loopback/link-local/reserved/CGNAT addresses rejected) and re-resolved afterwards (a rebinding inside the fetch window is detected and the content discarded).
- **Issuance bound**: the issued quantity is clamped to the project's remaining annual cap, so repeated verifications cannot exceed it; a project at its cap refuses further evidence.
- **Sole ownership**: transfer and settlement require the current owner as the sender; the zero address is rejected as a counterparty.
- **No double spend**: only `issued` lots can be transferred, settled or retired; `settling` lots can only be released or cancelled; `settled` and `retired` are terminal.
- **No lost payments**: the settlement value is escrowed by the registry; `release_settlement` pays the beneficiary, and `cancel_settlement` (after the window) returns the value to the seller. The credit only changes hands on release.
- **No stranded funds**: the registry holds settlement value only while a settlement is pending, and every pending settlement has a guaranteed exit.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/carbon_registry.py
```

30 GenVM direct-mode tests pass. Lint passes. E2E passes on studionet (see below). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0x4f57A7F3136222B6d433E6756316708Cd41bC8c2`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x02c1db9353382db893cd5f1f77a629649cc131b4bf63ceb2691ce366dd92d201`
**Source SHA-256:** `DCCAFEE29118CD252C68D960981F1938FE2B670F3D9D829FCF8AA368F93DE059`
**Status:** Deployed and tested on studionet.

Live E2E on studionet (scripts `e2e-test.cjs` + `resume-e2e.cjs`), every consensus step MAJORITY_AGREE:
- **register_project** → `P0` (cap 5000 `Mt CO2e`, source key `EN.GHG.CO2.MT.CE.AR5`, beneficiary `0xe57A…6614`).
- **submit_evidence** — beneficiary-signed, source `api.worldbank.org` World Bank indicator `EN.GHG.CO2.MT.CE.AR5` (the source key is present in the live document body — attribution checked deterministically).
- **verify_evidence** — MAJORITY_AGREE **on attempt 1**: live value 642.0878 → canonical **642100 milli = 642.1 Mt CO2e** minted as lot `VCS-P0-0`.
- **transfer_credit** → owner became the buyer.
- **settle_credit** (0.01 GEN) → state `settling`, value escrowed → **release_settlement** → state `settled`, beneficiary balance rose by exactly `10000000000000000` wei.
- **Second project** `P1` → signed evidence → **verify MAJORITY_AGREE on attempt 1** → lot `VCS-P1-1` (again exactly 642100 milli — two independent consensus runs binding the identical quantity) → settled and released (beneficiary +0.01 GEN).
- **Periodic reporting**: `P1`'s second monitoring period verified under consensus (attempt 1, 642100 milli) → second lot `VCS-P1-2` issued under the same annual cap → **retire_credit** → state `retired` (final).
- Final `registry_totals`: `credits_issued 3`, `projects 2`, `total_issued_milli 1926300`, `total_retired_milli 642100`, `total_settled_milli 1284200`, `total_settlement_value 2e16` — issued = settled + retired + held (0), no lot double-spent, no value stranded.

---

## Extension ideas

- Vintage years and expiry per lot, with a sweep of expired lots
- On-chain beneficiary rotation (change the payout address of a project)
- Batch issuance: one verification covering several monitoring periods
- Registry fee in GEN, distributed to the oracles that verified the evidence
- Cross-registry import: recognise a lot issued by another registry
