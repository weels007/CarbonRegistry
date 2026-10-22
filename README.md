# CarbonRegistry — Verified Carbon Credit Registry with a Serial Ledger

> **A project registers its methodology, an annual issuance cap and a beneficiary.** Evidence of real emission reductions is submitted and checked under consensus: the LLM extracts the *reported quantity* from the retrieved document, and the contract issues that amount as a uniquely serialised credit lot. Credits can be transferred, settled (the payment flows to the project beneficiary) or retired — each serial exactly once, so a credit can never be double-spent.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-28%20passed-16a34a?style=for-the-badge)](https://github.com/)

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

1. **Register a project** — `register_project(name, methodology, beneficiary, annual_cap, unit)`. The cap and the quantity unit are declared once; the beneficiary is the party that receives settlement payments.
2. **Submit evidence** — the beneficiary submits a monitoring report URL plus an EIP-191 signature bound to `{project_id}:{url}:{description}`.
3. **Verify** — anyone calls `verify_evidence`. Validators fetch the report and the LLM extracts the reported quantity; consensus compares the independently extracted numbers.
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
- **The model extracts a quantity, it does not judge.** It reads the amount the report states; the number of credits issued is derived on-chain from that number and clamped to the registered cap. No score decides value, and no model computes a price.
- **The unit is declared on-chain.** Each project records the unit its reports use (`t CO2e`, `Mt CO2e`), so the ledger is self-describing and the cap and the quantities are always in the same unit.
- **Evidence sources are submitter-independent.** A project cannot present a page it controls; only registries and public statistical agencies are fetchable, and the source is resolved over DNS-over-HTTPS before and after every request.
- **Settlement is two-step on purpose.** The buyer's payment is held by the registry and only reaches the beneficiary on an explicit release; if that never happens, the seller can cancel and get the money back. A credit can therefore never be paid twice *and* a buyer can never be stuck.
- **Periodic reporting.** A project may submit a new monitoring period and receive additional lots until its annual cap is reached — issuance stops at the cap, not at the first report.

---

## Consensus design

`verify_evidence` uses `run_nondet_unsafe` with the Equivalence Principle:

- **Leader**: fetches the evidence through the trusted fetch path and asks the LLM for the reported amount in integer thousandths (the calldata layer cannot encode floats).
- **Validator**: independently fetches and extracts, then compares: equal, or within ±5 % (basis points) with a floor of one unit.
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

28 GenVM direct-mode tests pass. Lint passes. E2E passes on studionet (see below). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0x1FdE631E82840f2D92e6Be0Bf9867f3a2170b7Bb`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x3e2664d408e995e8234bffa79d8c30731d02637739981419ce1ef1593c1c6ffe`
**Status:** Deployed and tested on studionet.

Live E2E (script `scripts/e2e-test.cjs`), every step MAJORITY_AGREE:
- **register_project** → `P0` (cap 5000 `Mt CO2e`, beneficiary `0xe57A…6614`).
- **submit_evidence** — beneficiary-signed, source `api.worldbank.org` indicator `EN.GHG.CO2.MT.CE.AR5`.
- **verify_evidence** — validators fetched the live World Bank response and the LLM extracted the reported amount: **642,088 milli = 642.088 Mt CO2e** → lot `VCS-P0-0` issued to the beneficiary.
- **transfer_credit** → owner became the buyer.
- **settle_credit** (0.01 GEN) → state `settling`, value escrowed → **release_settlement** → state `settled`, and the beneficiary's balance rose 0.06 → 0.07 GEN.
- **Second project → issue → retire** → lot retired against a compliance claim; retired is final.
- Final `registry_totals`: `credits_issued 2`, `total_issued_milli 1284176`, `total_retired_milli 642088`, `total_settled_milli 642088`, `total_settlement_value 1e16` — one lot settled, one retired, none double-spent.

---

## Extension ideas

- Vintage years and expiry per lot, with a sweep of expired lots
- On-chain beneficiary rotation (change the payout address of a project)
- Batch issuance: one verification covering several monitoring periods
- Registry fee in GEN, distributed to the oracles that verified the evidence
- Cross-registry import: recognise a lot issued by another registry
