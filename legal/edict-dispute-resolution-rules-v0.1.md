TESTNET EVALUATION RULES. These rules have not been independently reviewed and
do not create production legal assurance. They are not legal advice.

# Edict Dispute Resolution Rules

**Version 0.1 (2026) — rules identifier `edict-drr-v0.1`**

*Terminology is aligned to the Edict core schemas (`packages/core/src/types.ts`)
where a machine-readable counterpart exists. Machine identifiers appear in
`code font`.*

---

## PART A — INTERPRETATION AND APPLICATION

### Rule 1 — Statement of purpose

1.1 The purpose of these Rules is the rapid, confidential and cost-proportionate resolution of commercial disputes arising out of transactions formed or performed by autonomous software agents, including disputes over digital deliverables, escrowed value, machine-readable orders and smart-contract outcomes.

1.2 These Rules are designed so that a determination is reached in hours, may be applied automatically by a customer- or rail-controlled settlement system where the parties have so arranged, and — where the parties have selected the corresponding enforcement tier — is capable of being adopted as an arbitral award enforceable under the New York Convention.

1.3 These Rules are rail-neutral: they assume no particular blockchain, payment network, escrow standard or inference vendor.

### Rule 2 — Definitions

In these Rules:

(a) **automatic dispute resolution process** means a process associated with an order, escrow arrangement, digital asset or digital-asset system that is intended to resolve a dispute between the parties by the automated constitution and operation of an adjudicator or panel of adjudicators — **expressly including one or more artificial-intelligence systems constituted as a tribunal under Part F** — whose determination is implemented directly within the relevant settlement system, including by releasing, dividing, returning or re-scheduling escrowed value or by operating, modifying, cancelling, creating or transferring digital assets;

(b) **AI Tribunal** means the panel of artificial-intelligence adjudicator seats constituted under Rule 21 for a given Case;

(c) **order mandate** means the signed, machine-readable instrument (current schema `edict-om-2`; legacy schema `edict-om-1`) by which the parties record the transaction. A conforming `edict-om-2` instrument comprises at minimum: the parties and their agent or wallet identifiers; the description of the work; the acceptance criteria (including any machine checks); the price and settlement currency; the deadline; the acceptance window; the Legal Profile; the Legal Policy; the Decision Space; the Settlement Binding; the enumerated Material Adverse Exception events; and a nonce. Principal KYB and authority-credential references are required only where the Legal Policy selects `enterprise_legal` assurance under paragraph (hC);

(d) **evidence commitment** means a cryptographic commitment to an item of evidence, comprising the SHA-256 hash of the item's canonical bytes, the identity of the submitter (`requester`, `worker`, `venue`, `system` or, for a procedure that expressly permits it, `third_party`), the evidence kind, its authentication status, and optionally a sealed-storage locator, the content itself remaining sealed off-chain per Rule 17; DRR v0.1 does not itself create a third-party submission procedure;

(e) **enforcement tier** means the tier of legal effect selected in the Legal Profile, being one of:
  - **E0 (code only)** — the determination is applied solely by the customer- or rail-controlled settlement system and the parties intend no legal effect beyond the protected amount;
  - **E1 (contractually binding)** — the outcome of the automatic dispute resolution process is binding on the parties as a matter of contract (Rule 5), including where the parties have designated the process as an expert determination;
  - **E2 (arbitral award)** — the dispute is referred to arbitration and a natural-person arbitrator reviews the record and may adopt, vary or reject the Protocol Determination as their award under Part H;
  - **E3 (institutional forum)** — the Case is administered under the rules of a recognised institution designating the protocol as its resolution engine, as separately agreed;

(f) **Decision Space** means the closed, machine-readable set within which a tribunal may decide (`OrderMandate.decisionSpace`). DRR v0.1 applies only where its kind is `escrow_branches`; **Permitted Rulings** means the non-empty `permitted` list within that Decision Space, selected from the following vocabulary:
  - `requester_wins` — the escrowed value (or the disputed amount) is awarded to the requester;
  - `worker_wins` — the escrowed value (or the disputed amount) is awarded to the worker;
  - `split` — the disputed amount is divided, expressed in basis points (0–10,000) payable to the requester with the remainder to the worker;
  - `redo` — the worker is directed to re-perform, with a new deadline expressed as a specific time;
  as restricted for each Case by the signed Decision Space (Rule 7);

(g) **Case** means a dispute commenced under Rule 8, represented by a canonical case object comprising the case type and publicity setting; the parties; the order-mandate hash; the Legal Policy hash; any delivery-manifest hash; the evidence commitments; the value in USD; the Value Tier; the custody mode; the rail reference; the Legal Profile; the opening time; the Decision Space; and, where applicable, the append-only round context and effective deadline;

(h) **Legal Profile** means the per-transaction selection, recorded in the order mandate, of governing law, seat, rules body and enforcement tier (schema fields `governingLaw`, `seat`, `rules`, `enforcementTier`);

(hA) **Legal Policy** means the versioned object embedded in `edict-om-2` and bound by its canonical SHA-256 hash, recording: the assurance mode; the Rules identifier, version, exact Rules Hash and retrieval location; the challenge window; the complete human-escalation election; E2 implementation timing; the Bond removal destination; and, where used, the Customer Policy Pack reference;

(hB) **Customer Policy Pack** means a versioned, content-addressed module which identifies the exact source terms and states normalized rules of decision with source-clause references. It records the fixed order of precedence: mandatory law, the order mandate, customer policy, then these Rules. Raw customer terms are evidence only and do not become tribunal instructions merely because they are submitted;

(hC) **assurance mode** means the identity and legal-assurance basis selected in the Legal Policy, being one of:
  - **`wallet_native`** — the parties are identified by the signing wallet or agent key; the signature is treated by the settlement system as self-authority for that key, no KYB or principal-to-agent delegation is required by Edict, and only enforcement tier E0 may be selected;
  - **`rail_verified`** — the settlement rail supplies its own authenticated party references and eligibility controls without disclosing underlying identity records to Edict; only enforcement tier E0 may be selected, and a customer seeking a higher tier must instead select `enterprise_legal`; or
  - **`enterprise_legal`** — each agent acts for a verified legal principal under an authenticated, scoped and revocable authority credential, and enforcement tier E1, E2 or E3 may be selected;

(hD) **Settlement Binding** means the signed `edict-om-2` field which records: (i) `M2_external_escrow` or `M4_no_custody`; (ii) the funds controller, being the requester wallet, a customer-controlled contract, a customer-approved immutable or keyless settlement contract, or the payment rail; (iii) the versioned adapter reference; (iv) that the Protocol Operator cannot transfer or freeze the protected funds and is not a required settlement signer; (v) the resolution timeout and liveness fallback; and (vi), where confidential transport or settlement is selected, the confidentiality mode, exact capability-evidence hash, exact disclosure-policy hash, privacy fallback and, if public fallback is permitted, the exact alternate public-adapter reference. Omission of the confidentiality object means public settlement. A conforming production settlement arrangement must also ensure that neither the Protocol Operator nor the Tribunal Entity holds or receives any private key, MPC share, withdrawal credential, owner or upgrade key, pause or freeze right, policy-admin right or other means of unilateral disposal or restraint. Reliance on an independent payment, privacy or interoperability protocol must be separately disclosed and does not make that protocol's governance, validator, upgrade, pause, visibility or liveness risk an Edict power;

(hE) **Settlement Directive** means the data object derived from the signed order mandate, Case and effective final Protocol Determination, binding the case id, order-mandate hash, verdict hash, Settlement Binding, rail reference and permitted action. It is not itself a transaction, credential or transfer instruction capable of moving funds without independent application by the funds controller;

(i) **requester** means the party, wallet or agent that opened and funded the order; **worker** means the party, wallet or agent engaged to perform and be paid. In `enterprise_legal` mode, the party includes the verified legal principal for whom an agent acts (Rule 3.3);

(j) **Value Tier** means Tier A (value below USD 10), Tier B (USD 10 through USD 1,000) or Tier C (USD 1,000 through USD 100,000), as assigned under Rule 11; at exactly USD 1,000 either Tier B or Tier C may be recorded, with Tier B the default;

(k) **Protocol Determination** means the verdict object issued by the AI Tribunal or the Human Bench for a Case, comprising the ruling, the reasoning hash, the seat votes and proofs, and the quality gates;

(l) **Human Bench** means the standing panel of natural persons constituted by the Tribunal Entity to hear final protocol appeals under Rule 27;

(m) **Adopting Arbitrator** means the natural-person arbitrator appointed under Rule 28;

(n) **Tribunal Entity** means the legal entity under whose charter Protocol Determinations are issued as corporate acts and which maintains the Human Bench and the arbitrator bench (see the tribunal-entity term sheet);

(o) **Protocol Operator** means the operator of the Edict software, registries and case pipeline, an entity distinct from the Tribunal Entity;

(p) **Infrastructure Operator** means a person operating attested inference infrastructure on which one or more AI Tribunal seats run;

(q) **Model Family** means a lineage of related artificial-intelligence models sharing a common base architecture and training provenance, such that two models of the same family cannot be treated as independent adjudicators;

(r) **registered endpoint** means an electronic address (API endpoint, on-chain inbox, or messaging address) registered for a party with the protocol at credential issuance or designated in the order mandate, at which that party agrees to receive service;

(s) **challenge window** means the period after issue of a Tier B Protocol Determination within which a party may challenge it, being not less than 2 nor more than 24 hours as fixed in the signed order mandate, signed profile or other signed incorporating instrument, and 24 hours in default;

(t) **Bond** means the amount a party must commit to open, challenge or appeal a Case under Rule 15;

(u) **Material Adverse Exception (MAE)** means an event enumerated in the order mandate on the occurrence of which an on-chain outcome is not deemed contractual performance (Rule 33);

(v) **attested signature** means a digital signature over the tuple {model identifier, SHA-256 of request, SHA-256 of response} produced by a key whose provenance is bound to hardware attestation of the executing environment and registered in the protocol's attestation registry;

(w) **Rules Hash** means the SHA-256 hash of the canonical UTF-8 text of a published version of these Rules (Rule 35);

(x) **digital asset** includes a cryptoasset, token, smart contract, escrowed balance or other digital or coded representation of an asset, obligation or transaction, and **digital-asset system** means the environment in which it exists;

(y) **hours** means clock hours; all periods are computed continuously, without exclusion of non-business days, consistent with an always-on process; and

(z) references to a **tribunal** without qualification mean the AI Tribunal, the Human Bench, or the Adopting Arbitrator, as the context of the applicable tier and round requires.

### Rule 3 — Scope of application

3.1 These Rules are intended for bilateral transactions in which each party enters in the course of a business, including transactions concluded by software agents on behalf of business principals. Each party warrants that it does not contract under these Rules as a consumer.

3.2 These Rules must not be incorporated into a contract with a natural person acting outside a trade, business or profession. Where mandatory consumer-protection law nonetheless applies to a party, nothing in these Rules deprives that party of protections that cannot lawfully be waived, and the remainder of the Rules applies to the fullest permitted extent.

3.3 **Identity assurance is mode-specific.** In `wallet_native` mode, the signed wallet or agent key is the protocol identity and is treated as acting for itself; Edict does not require KYB or infer a separate legal principal. In `rail_verified` mode, Edict may rely on the rail's authenticated opaque party reference for protocol purposes, while the rail remains responsible for controls it represents that reference as satisfying. In `enterprise_legal` mode, KYB identifies and verifies the legal principal, including the business-status facts required for eligibility, service, sanctions screening and conflict checks, but does not authorize an agent. A conforming authority credential (`edict-authority-1`) must separately record the principal's authenticated delegation, credential identifier, principal KYB reference, agent key, permitted actions, transaction-value and rail/currency limits where applicable, validity period, issuer and signing key, revocation registry and nonce, and proof. The order mandate binds the credential hash. Where that credential was valid, within scope and unrevoked when the agent acted, the act is attributed to the principal, subject to proven compromise and mandatory agency law.

3.3A A rail, venue or party remains responsible for any identity, sanctions, anti-money-laundering, consumer, tax or market-access duty imposed on it by law or by its own service terms. Selection of `wallet_native` or `rail_verified` means only that Edict does not impose a separate universal KYB workflow; it is not a representation that no external obligation applies.

3.4 These Rules apply to any dispute arising out of or in connection with an order mandate that incorporates them, including disputes as to delivery, conformance, non-performance, payment, the operation of the escrow, and Material Adverse Exception claims (Rule 33), but excluding matters that are not arbitrable or determinable by contract under the applicable law.

3.5 DRR v0.1 supplies procedure only for a `bilateral` Case with an `escrow_branches` Decision Space. The core schema's `public_resolution` and `claim` case types, and its `categorical` and `bounded_scalar` Decision Spaces, require a later rules version or an express signed modification that supplies a complete compatible procedure. They must not be presented as governed by unmodified DRR v0.1.

3.6 Customer standard terms may supplement these Rules only through a Customer Policy Pack referenced by the signed Legal Policy before the order is funded. A Policy Pack may define transaction-specific standards, exclusions, evidential presumptions and remedies within the signed Decision Space, but may not displace mandatory law, expand the Decision Space, make a non-final verdict executable, remove a party's opportunity to address the record, or contradict these Rules unless the signed modification identifies the affected rule expressly and is legally effective.

3.7 **Operational separation is mandatory for production use.** The protected amount and every Bond must remain with the funds controller identified by the Settlement Binding or with an independent pool or safeguarding provider selected by that controller. The Protocol Operator and Tribunal Entity provide adjudication, verification and case-administration services only. Neither may receive protected principal or Bonds into its own wallet, bank account or omnibus ledger; possess or use a customer custody credential; be the unique or privileged submitter of a settlement transaction; or hold an ad hoc power to release, redirect, freeze, delay or upgrade the mechanism controlling funds. The Protocol Operator may sponsor gas or relay a proof package only through the same permissionless entry point available to any other account and only where its absence does not impair correctness or liveness. Any on-chain verifier quorum must remain satisfiable without Protocol-Operator-controlled signers and must not be satisfiable by those signers alone. Fees due to either must be charged separately from protected principal and Bonds unless the customer-controlled settlement system makes a pre-committed, disclosed deduction without granting either entity control of the funds.

### Rule 4 — Incorporation

4.1 These Rules may be incorporated into a contract, order mandate, digital asset or digital-asset system **by text**, by including words to the effect: *"Any dispute shall be resolved in accordance with the Edict Dispute Resolution Rules, version `edict-drr-v0.1`."* The incorporating text may be in electronic or encoded form.

4.2 These Rules may equally be incorporated **by code**. A conforming `edict-om-2` order embeds the Legal Policy, and the wallet-signable envelope binds the canonical Legal Policy hash, assurance mode and exact Rules Hash. The Legal Profile's rules identifier and the Legal Policy's Rules reference must agree. A legacy `edict-om-1` instrument has no dedicated Rules Hash field and is not suitable for an external E1 or E2 launch unless another instrument signed by both parties supplies the omitted hash and policy elections. An unsigned interface display does not incorporate or vary them.

4.3 Incorporation by hash prevails over incorporation by identifier: where a Rules Hash is embedded, the version of the Rules whose canonical text produces that hash governs the Case (Rule 35.3). Where only the identifier is embedded, the version current at the time the order mandate was signed governs.

4.4 The incorporating instrument may additionally specify: (a) that a defined issue class be resolved by expert determination rather than by the default process; (b) an `escrow_branches` Decision Space containing the Permitted Rulings available; (c) the challenge window within the bounds of Rule 2(s); (d) the human-escalation mode and parameters; (e) E2 implementation timing; (f) a Customer Policy Pack; (g) preferences as to the Adopting Arbitrator under Part H; and (h) any express modification to these Rules, provided that no modification may enlarge the tribunal's powers beyond the signed Decision Space or remove the consent required by Rule 5.

4.5 The canonical text identified by the rules identifier and any Rules Hash must be made reasonably available to each party before signature and retained in a durable record accessible after signature. These Rules do not displace any mandatory requirement for reasonable notice, express assent, form or accessibility governing incorporation by reference.

---

## PART B — CONSENT AND EFFECT

### Rule 5 — Consent to automatic dispute resolution by AI tribunal

5.1 By incorporating these Rules the parties agree that any dispute within Rule 3.4 shall first be resolved by an automatic dispute resolution process, and the parties **expressly acknowledge and consent** that the tribunal constituted for that process comprises artificial-intelligence systems, configured and operated as described in Part F, and not natural persons.

5.2 Each party irrevocably waives, to the fullest extent permitted by applicable law, any objection to a determination under these Rules founded on the adjudicator not being a natural person, on the automated character of the process, or on the absence of an oral hearing.

5.3 Only an effective final Protocol Determination, after resolution of every hold or review route pre-committed under Rule 25.3, is **legally binding on the parties as a matter of contract**. A verdict marked non-final or escalated has no binding or executable merits effect; it may only trigger the pre-committed fallback, review or appeal route. At enforcement tier E1, the effective final Protocol Determination binds as a contractual determination (or, where so designated under Rule 4.4(a), as an expert determination). At enforcement tier E2, it additionally serves as the record and proposed determination placed before the Adopting Arbitrator under Part H, and the parties agree that the arbitral tribunal for the purposes of the applicable arbitration law is the Adopting Arbitrator, a natural person.

5.4 At enforcement tier E0 the parties intend the determination to operate solely within the settlement system, and no obligation enforceable outside that system arises from the determination itself.

### Rule 6 — Enforcement tiers

6.1 The enforcement tier for a Case is the tier recorded in the Legal Profile of the order mandate. A conforming `edict-om-2` mandate must record it. If an otherwise effective non-machine incorporating instrument omits it, tier E1 applies to Tier B Cases and tier E2 to Tier C Cases. **Tier E0 applies to Tier A Cases in every event, and any inconsistent machine field is invalid and must be rejected or normalized to E0 before funding.**

6.2 The tiers are cumulative: each higher tier includes the effect of the tiers below it. A party's rights under a higher tier are not diminished by the availability of a lower tier.

6.3 The Legal Policy must elect `implement_then_arbitrate` or `hold_pending_award` for E2. Under `implement_then_arbitrate`, the Protocol Determination is implemented under Rule 25 upon resolution of applicable holds and the arbitral layer operates on and above that outcome. Under `hold_pending_award`, settlement remains held until the award. A rail must not offer an election it cannot execute. The standard v0.1 policy is `implement_then_arbitrate`.

6.4 An `edict-om-2` mandate selecting `wallet_native` or `rail_verified` assurance must select E0. E1, E2 and E3 require `enterprise_legal` assurance and the identity and authority evidence described in Rule 3.3. A non-conforming combination must be rejected before funding and must not be normalized silently to a higher assurance mode.

### Rule 7 — Permitted rulings

7.1 A Case under DRR v0.1 must contain a valid `escrow_branches` Decision Space with a non-empty `permitted` list. A tribunal may select only among that list. A Case must not commence if the Decision Space is absent, empty or of another kind; there is no implied all-rulings fallback in the machine procedure.

7.2 A ruling of `split` must state the requester's share in basis points from 0 to 10,000; the remainder is the worker's. A ruling of `redo` must state a later deadline as a specific time. V0.1 permits **one redo only**. The first-round record and Bond remain held; any second adjudication is recorded as round 2 against the effective deadline; and `redo` is unavailable in round 2.

7.3 The tribunal has no power to determine any payment allocation other than by selection of a Permitted Ruling whose effect was pre-committed in the signed order mandate and Settlement Binding. The resulting Settlement Directive is applied, if at all, by the funds controller. Restricting destinations is a bounded-remedy safeguard and does not by itself establish that an arrangement is non-custodial; the operational separation in Rule 3.7 must also hold.

7.4 Nothing in this Rule limits the relief an Adopting Arbitrator may grant under Part H in respect of amounts or obligations beyond the escrowed collateral, provided the arbitrator's award in respect of the escrowed collateral itself is expressed by reference to the Permitted Rulings.

---

## PART C — COMMENCEMENT AND SERVICE

### Rule 8 — Commencement

8.1 A party (the **claimant**) commences a Case by submitting a notice of dispute through the protocol before expiry of the acceptance window stated in the order mandate (or, for claims of non-delivery, at any time after the deadline stated in the order mandate), and by committing the Bond required by Rule 15.

8.2 The notice of dispute must include:
(a) the order-mandate hash and rail reference identifying the transaction;
(b) the claimant's agent, wallet or rail identifier and, only in `enterprise_legal` mode, its principal KYB reference (subject to Rule 32);
(c) the claimant's registered endpoint;
(d) a concise statement of the claim and of the ruling sought from among the Permitted Rulings;
(e) the claimant's evidence commitments; and
(f) confirmation that the Bond and the applicable fee have been committed.

8.3 A Case is commenced when the protocol records acceptance of a conformant notice of dispute. The protocol assigns the Value Tier under Rule 11 at commencement.

### Rule 9 — Digital service

9.1 Every notice, response, submission and determination under these Rules is served digitally by delivery to the recipient party's registered endpoint, and service is effective upon the protocol recording delivery to that endpoint.

9.2 Each party is responsible for maintaining a functioning registered endpoint and for monitoring it. A party's failure to monitor its registered endpoint does not invalidate service.

9.3 Where delivery to a registered endpoint fails, the protocol shall attempt each fallback endpoint registered for the party, and service is effective upon the first recorded delivery; if all attempts fail, service is deemed effective 12 hours after the first attempt, provided the attempts are logged as evidence commitments of kind `system`.

### Rule 10 — Response

10.1 The respondent shall submit a response within **24 hours** of service of the notice of dispute for a Tier B Case, and within **72 hours** for a Tier C Case.

10.2 The response must include the respondent's registered endpoint and the mode-appropriate identity details corresponding to Rule 8.2(b), and may include a statement of position, evidence commitments, and any objection to tier assignment or to the application of these Rules.

10.3 Failure to respond within time does not prevent the Case proceeding. The tribunal shall not treat silence as an admission, but shall determine the Case on the record before it.

---

## PART D — TIER PROCEDURE

### Rule 11 — Value tiers; tier assignment

11.1 The protocol assigns the Value Tier from the value in USD of the amount in dispute, valued at commencement: Tier A below USD 10; Tier B from USD 10 through USD 1,000; Tier C from USD 1,000 through USD 100,000. At exactly USD 1,000, either Tier B or Tier C is valid if recorded in the Case; Tier B applies in default.

11.2 Disputes exceeding USD 100,000 are outside this version of the Rules and must not be commenced through the standard protocol. The parties and Tribunal Entity may agree a separate procedure, but it is not a Case under DRR v0.1 unless and until a later rules version and compatible schema expressly permit it.

11.3 An objection to tier assignment is determined summarily by the protocol against the order mandate's price and settlement records, before constitution of the tribunal.

### Rule 12 — Tier A procedure (pooled protection claims)

12.1 Tier A Cases are not individually adjudicated as adversarial proceedings. A Tier A claim is a claim on a protection pool funded by protection premiums and operated by the customer, payment rail or a separately appointed independent pool provider. It may be auto-settled by a single AI adjudication pass applying the order mandate and the burden defaults of Rule 19. The Protocol Operator and Tribunal Entity must not hold or control the pool.

12.2 Tier A payouts are subject to per-identity caps per epoch as published in the protocol's fee and caps schedule, and to the registration stake requirements applicable to agent identities.

12.3 A random sample of not less than 2% of Tier A settlements in each epoch is audited under Tier B procedure. Where an audit finds a claim to have been dishonestly made or dishonestly resisted, the protocol may impose the published penalty, which shall be set at a level not lower than the expected gain divided by the audit probability, and may suspend the identity's access.

12.4 Tier A determinations are enforcement tier E0 in every event (Rule 6.1). No challenge or appeal lies from a Tier A settlement other than the audit in Rule 12.3.

### Rule 13 — Tier B procedure

13.1 On commencement of a Tier B Case and receipt of the response (or expiry of the response period), the protocol constitutes an AI Tribunal of **three seats** in accordance with Rule 21 and places the sealed record before it.

13.2 The AI Tribunal shall use its best endeavours to issue its Protocol Determination within **1 hour** of the record closing (that is, of the later of the response, the expiry of the response period, or the completion of any evidence direction under Rule 17.4).

13.3 A final Protocol Determination takes effect and is implemented under Rule 25 only after the challenge window and every review hold under the signed Legal Policy have expired or been resolved.

13.4 Where the Legal Policy elects `optional_appeal`, either party may invoke human review under Rule 26 within the signed appeal window by committing the signed appeal Bond and paying any disclosed review fee. Other modes do not create a party appeal merely because the Case is Tier B.

13.5 Costs of a Tier B Case follow Rule 15.

### Rule 14 — Tier C procedure

14.1 On commencement of a Tier C Case (or referral under Rule 13.4), the protocol constitutes an AI Tribunal of **five seats** in accordance with Rule 21.

14.2 Tier C determinations are issued by **commit–reveal**: each seat first submits a cryptographic commitment to its ruling and reasoning hash; only after all commitments are recorded (or the commitment period expires) are the votes revealed. A seat that reveals a vote not matching its commitment is discarded and its Infrastructure Operator reported under the operator-staking policy.

14.3 The periods are: commitments within **48 hours** of constitution; reveal within **12 hours** after the close of commitments; Protocol Determination assembled and issued within **72 hours** of constitution.

14.4 The ruling is that of the **majority** of unexcluded seats. If no ruling kind commands a majority (after applying Rule 22.4), the Case escalates one round under Rule 26 without any party's Bond being forfeited for that round.

14.5 A final Protocol Determination takes effect and is implemented under Rule 25 only after the signed challenge window and every review hold under Rule 26 have expired or been resolved.

### Rule 15 — Bonds, fees and costs

15.1 The Bond to open a Tier B or Tier C Case is the percentage of the amount in dispute published in the protocol's fee schedule, being not less than 5% nor more than 10%, with a floor of USD 1. Fees of the protocol and, where applicable, of the Tribunal Entity, the Human Bench and the Adopting Arbitrator are as published in that schedule or fixed at appointment.

15.2 Each challenge or appeal requires a Bond of **twice** the Bond of the round below (the doubling ladder), committed by the challenging or appealing party.

15.3 Subject to Rule 15.4, on final determination of a Case within the protocol (including the Human Bench round):
(a) the unsuccessful party bears the tribunal fees for each round it lost, which may be deducted from an amount otherwise returnable from its Bond;
(b) **one half** of that party's forfeited Bond principal is paid to the counterparty;
(c) the residual forfeited Bond principal, including any indivisible rounding residual, is sent by the funds controller to the destination signed in the Legal Policy: `protocol_burn` only where the rail provides a verifiable irreversible sink, and otherwise `protection_pool`. A protection pool must be operated by the customer, rail or a separately appointed independent provider, separately accounted for, and used only for disclosed protection claims and costs. Neither the pool nor its assets may be controlled by, or recognized as revenue of, the Protocol Operator or Tribunal Entity; and
(d) a party awarded the whole disputed amount has its Bond principal returned in full, subject to any fee deduction under paragraph (a).

15.4 On a `split` ruling, each party's **awarded share** is the share of the disputed amount allocated to it: the stated requester basis points for the requester and the remainder to the worker. For each Bond posted by a party:
(a) the gross Bond refund equals that Bond multiplied by that party's awarded share;
(b) the remaining Bond principal is forfeited;
(c) after accounting separately for any fees allocated under Rule 15.3(a), one half of the forfeited principal is paid to the counterparty and the residual is dealt with under Rule 15.3(c); and
(d) calculations use the smallest unit supported by the settlement system, with multiplication rounded down and any indivisible residual allocated under Rule 15.3(c).

On a `redo` ruling, the original Bond is held without refund or forfeiture until conformant re-delivery, acceptance, timeout or round-2 determination. No second opening Bond is charged to the original disputant. The Bond is then allocated according to the final outcome. `Redo` does not itself constitute success or failure for Bond allocation.

15.5 The customer- or rail-controlled settlement system applies the formula in Rules 15.3–15.4 without discretion. A Human Bench or Adopting Arbitrator may make a separate fee or costs order for misconduct, including a contaminated submission under Rule 20.4, only to the extent permitted by the signed Legal Policy, the applicable enforcement tier and governing law; it may not cause the settlement system to execute a payout branch or Bond destination that was not pre-committed.

### Rule 16 — Timelines; computation and extension

16.1 All periods run in hours from the recorded protocol event that starts them, continuously and without exclusion of weekends or holidays (Rule 2(y)).

16.2 The parties may jointly agree, or the tribunal for the round may direct on its own motion for good cause, one extension per round of up to the length of the original period. Any further extension requires the Tribunal Entity's approval, recorded on the Case with reasons.

16.3 Failure to meet a target in Rules 13.2, 14.3, 27.4 or 30.3 does not invalidate a determination or award, but persistent failure is reportable under the Tribunal Entity's service standards.

---

## PART E — EVIDENCE

### Rule 17 — Evidence commitments; sealed evidence

17.1 Evidence is submitted by evidence commitment. The content of each committed item is encrypted to the attested tribunal environment and remains sealed: it is readable only by the tribunal for the round, the parties, and — under protocol-governed re-encryption — any appellate tribunal, the Human Bench and the Adopting Arbitrator.

17.2 The recognised evidence kinds are those of the protocol schema: order mandate; Legal Policy; Customer Policy Pack; authority credential; delivery manifest; delivery receipt; interaction-log head; payment receipt; party submission; zkTLS proof; TEE runtime attestation; and C2PA manifest. Other material may be committed as a party submission.

17.3 A party must be able to produce, on the tribunal's direction, the plaintext whose hash matches its commitment. A commitment whose plaintext is not produced on direction is disregarded, and the tribunal may draw an adverse inference from non-production of material shown to exist.

17.4 The tribunal has discretion, exercised through the protocol, to direct a party to commit further identified material within a fixed period of not more than 12 hours (Tier B) or 24 hours (Tier C).

17.5 A delivery receipt evidences delivery only. **Receipt of a deliverable is not acceptance of it.**

### Rule 18 — The order mandate; acceptance criteria and machine checks

18.1 The order mandate is the primary instrument for every Case. The tribunal shall determine conformance of the work against the acceptance criteria stated in the order mandate, and shall not substitute criteria of its own.

18.2 Where an acceptance criterion carries a machine check (hash equality, schema validation, deadline comparison, content inclusion, or a custom deterministic check), the result of the deterministic execution of that check on the committed evidence is conclusive of that criterion, absent proof that the check itself was corrupted or that a Material Adverse Exception applies.

18.3 Criteria without machine checks are assessed on the evidence as a whole against the standard of a reasonable counterparty in the parties' line of business.

### Rule 19 — Burdens and presumptions

19.1 The claimant bears the burden of establishing its claim on the balance of probabilities, subject to the following defaults.

19.2 **Conformant-delivery shift.** Where the worker has committed a signed delivery manifest before the deadline, and the manifest and delivered artifacts satisfy on their face the machine-checkable acceptance criteria, delivery is presumed conformant and the **burden shifts to the requester-claimant** to establish non-conformance.

19.3 **Ambiguity against the drafter.** Ambiguity in an acceptance criterion or in the description of the work is construed against the party that drafted or proposed it, as recorded in the order mandate's provenance; where provenance is not recorded, against the requester.

19.4 Absence of a delivery manifest by the deadline gives rise to a presumption of non-delivery, rebuttable by other authenticated evidence of conformant delivery.

19.5 A payment receipt of a recognised kind is presumed accurate as to the fact, time and amount of the payment it records.

### Rule 20 — Weight; authentication; contaminated material

20.1 The tribunal has discretion as to the weight of each item, subject to this Rule.

20.2 Authenticated material — material whose commitment is cryptographically signed by an identified party or produced by an attested system (delivery manifests, interaction-log heads, payment receipts, zkTLS proofs, TEE attestations, C2PA manifests) — is entitled to weight accordingly.

20.3 **Unauthenticated material is entitled to low weight**, and cannot alone displace a presumption arising under Rule 19 from authenticated material.

20.4 A submission found by the protocol's screening or by the tribunal to contain **prompt-injection or other content engineered to manipulate an artificial-intelligence adjudicator** (rather than to persuade on the merits) **may be disregarded in whole or in part**. The finding is recorded in the determination's quality record; the tribunal may sanction the submitting party in costs under Rule 15.5; and a screened Case may be escalated one round under Rule 26.4.

20.5 Party submissions are adversarial by construction and are argument, not testimony; assertions of fact in a party submission unsupported by authenticated material are entitled to minimal weight.

---

## PART F — THE AI TRIBUNAL

### Rule 21 — Composition; independence of infrastructure

21.1 An AI Tribunal is composed of adjudicator seats, each being a pinned artificial-intelligence model executing on attested confidential infrastructure of an identified Infrastructure Operator.

21.2 Composition constraints, enforced by the protocol at constitution:
(a) every seat on a tribunal must be of a **distinct Model Family** (disjointness across seats);
(b) seats must span **at least two** Infrastructure Operators (Tier B) or **at least three** (Tier C), and no single Infrastructure Operator may hold a majority of seats on any tribunal;
(c) for Tier C, seats shall additionally span at least two distinct hardware-attestation vendors where commercially available; and
(d) no seat may run on infrastructure operated by a party, by the venue on which the disputed transaction was made, or by an affiliate of either, except where that operator's seat cannot affect the majority and the composition is disclosed in the determination.

21.3 The seat roster (provider, model identifier, model family) for each Case is recorded in the Protocol Determination and is verifiable by the parties.

21.4 The parties consent to composition per this Rule and Rule 5. Objections to composition must be raised within the challenge window and are determined in the next round.

### Rule 22 — Determinism; dual-orientation review; replay

22.1 Each seat evaluates the Case deterministically: temperature-zero inference on a pinned model with byte-exact capture of request and response, such that the evaluation is reproducible from the recorded inputs (**deterministic replay**).

22.2 Each seat evaluates the record **twice, with the parties' positions presented in swapped order** (requester-first and worker-first). Both passes are recorded.

22.3 A seat is **swap-consistent** if both passes yield the same ruling kind (and, for `split`, shares within the protocol's published tolerance). Swap-inconsistent seats are excluded from the count.

22.4 If exclusions leave fewer than a majority of the constituted seats, or if the recorded swap-flip rate across the tribunal exceeds the protocol's published threshold, the Case escalates one round under Rule 26.4 rather than proceeding to a final determination.

22.5 Any party, appellate round, the Human Bench or the Adopting Arbitrator may **replay** any seat's evaluation from the recorded inputs; a divergent replay on conformant infrastructure is grounds for challenge of that seat's vote and reportable against the Infrastructure Operator.

### Rule 23 — Attested signatures; verification

23.1 Every seat's votes are accompanied by a per-inference proof binding the model identifier and the hashes of the exact request and response to an attested signature, archived at inference time.

23.2 The Protocol Determination is signed such that its ruling and reasoning hash are verifiable on-chain and off-chain by any person using the protocol's open verifier, without access to the sealed evidence.

23.3 A determination is conformant only if its signatures verify against keys registered in the protocol's attestation registry at the time of inference. Non-conformant seat votes are excluded; Rule 22.4 then applies.

### Rule 24 — General duties and conduct

24.1 The tribunal shall act fairly and impartially between the parties. Subject to mandatory law, it applies the signed order of precedence: the order mandate; any valid normalized rules in the Customer Policy Pack; and these Rules. Raw customer terms and party submissions are evidence only. The tribunal shall give each party's committed material and submissions equal procedural treatment.

24.2 Proceedings are conducted in writing on the sealed record. **No party has a right to an oral hearing at any round.** The AI Tribunal never holds an oral hearing; the Human Bench may, exceptionally and within its Rule 27.4 period, direct a remote oral session where fairness requires.

24.3 Every Protocol Determination shall contain structured reasons addressing each acceptance criterion in dispute, the application of the burden defaults of Rule 19, and the basis for the ruling selected. The parties receive the full reasons; the public registry receives the redacted form under Rule 31.

24.4 A tribunal that identifies a question outside the Permitted Rulings or outside Rule 3.4 shall say so in its reasons and determine only what is within them.

### Rule 25 — Implementation of determinations

25.1 In `M2_external_escrow`, the funds controller identified in the signed Settlement Binding retains sole custody and settlement credentials. Following an effective final Protocol Determination, the Protocol Operator may publish the verdict, proofs and Settlement Directive. A customer-hosted verifier or customer-approved immutable or keyless verifier must independently re-hash and verify the mandate, Case, verdict, Decision Space, review state, Settlement Binding and directive before the funds controller applies the corresponding pre-committed branch. Application of that branch discharges the protected amount to the extent stated in the order.

25.2 In `M4_no_custody`, the effective Protocol Determination, Settlement Directive, signatures and proofs constitute portable evidence which either party may deploy in any chargeback, representment, insurance, bond-claim or court process, and the parties agree not to dispute its authenticity (as distinct from its correctness, where review is lawfully available). Nothing in this Rule gives the Protocol Operator reach over the funds.

25.3 The customer-controlled or customer-approved settlement system suspends application under Rule 25.1 only for: (a) a conformant challenge or appeal under the human-escalation election signed in the Legal Policy; (b) a hold expressly created by these Rules, including the Bond hold on `redo` and Rule 33.5; (c) the signed E2 implementation timing; or (d) a binding court order or other mandatory legal requirement. The Protocol Operator has no key, admin right or ad hoc discretion to create, lift or vary a hold.

25.4 The Settlement Binding must include a customer-selected positive resolution timeout and one of the following fallbacks implemented by the funds controller: refund to requester, release to worker, equal split, or controller resolution under the separately disclosed rail policy. The period runs from closure of the dispute record unless the signed order states another objective starting event. An Edict outage or failure to produce a valid final determination therefore cannot confer an indefinite Edict hold. The fallback must be disclosed before signature and must not convert an advisory or non-final verdict into an executable merits decision.

25.5 Where a confidentiality mode is selected, the funds controller shall apply only an adapter whose capability evidence matches the signed capability hash. `confidential_transport` means that transport is intended to conceal specified routing or transfer data but does not represent that a public settlement system conceals its own state. `confidential_settlement` may be represented only where the bound settlement state machine itself executes in the identified confidential environment and public output is limited in accordance with the signed disclosure policy. Unavailability or failed verification of that environment must fail closed and route only to a private refund or timeout path, unless `allow_public_settlement` and the complete public adapter and disclosure consequences were signed before funding. No party or system may infer consent to public settlement from silence, urgency or continued use.

---

## PART G — CHALLENGE, APPEAL AND HUMAN BENCH

### Rule 26 — Challenge and appeal

26.1 The Legal Policy must disclose one human-escalation mode:
(a) `off`: no human merits review is supplied by Edict;
(b) `optional_appeal`: a party may invoke human review of an otherwise final determination within the signed appeal window and on the signed appeal-Bond terms;
(c) `quality_gate`: only the signed quality triggers route a non-final determination to human review; or
(d) `required_above_value`: every Case at or above the signed USD threshold is held for human review, whether or not the AI determination is otherwise final, and signed quality triggers also apply.

26.2 The election must state the covered trigger set, any per-tier override, threshold, appeal window, appeal-Bond multiplier and reviewer pool where applicable. The wallet-signable `edict-om-2` envelope binds the canonical hash of the complete election. No interface, operator or party may change it after funding.

26.3 Under `optional_appeal`, an appeal is commenced within the signed appeal window by authenticated notice through the protocol and commitment of the signed appeal Bond. The AI determination remains on the record but settlement is held. Failure to appeal within that window permits the otherwise final determination to take effect.

26.4 Under `quality_gate` or `required_above_value`, a covered trigger or threshold routes the Case to the reviewer pool without fault and without Bond forfeiture merely because of the routing. A verdict marked non-final or escalated never becomes executable by expiry of time alone.

26.5 Under `off`, an escalated or non-final verdict remains non-binding and non-executable. On expiry of the resolution timeout it may route only to the liveness fallback stated in the signed Settlement Binding and executable by the funds controller. A production `edict-om-2` order without an implemented conforming fallback must be rejected before funding. The AI's advisory ruling is never silently treated as final or used to choose the fallback.

26.6 A Human Bench resolution under Rule 27 supersedes, but does not erase, the AI determination and is the only protocol verdict thereafter eligible for execution. No further appeal lies within the protocol. Recourse beyond it exists only at enforcement tiers E2 and E3 and as preserved by Rule 30.5.

### Rule 27 — The Human Bench

27.1 The reviewer pool is the pool signed in the Legal Policy: `edict_bench`, `customer_panel` or `external_arbitrator`. An Edict or customer panel is heard by **three natural persons**, each free of conflicts under the applicable recusal policy. An external-arbitrator route is heard by the appointed natural person under that provider's agreed terms. A customer panel may not include a person involved in the transaction or its disputed performance.

27.2 Human review is convened within **24 hours** of a conformant appeal, covered quality trigger or mandatory-value hold and receives: the full sealed record; every prior determination with full reasons; the seat rosters, proofs and quality records; and any replay results.

27.3 The Human Bench reviews de novo but with regard to the prior rounds' reasons, and selects among the Permitted Rulings, in writing, with reasons, by majority.

27.4 The Human Bench shall issue its determination within **96 hours** of being convened.

27.5 The determination of the Human Bench is the final Protocol Determination for the Case and is implemented under Rule 25.

---

## PART H — ENFORCEMENT TIER E2: ARBITRAL ADOPTION

### Rule 28 — Referral to arbitration; appointment

28.1 Where the Legal Profile selects tier E2 (or Rule 6.1 applies it), any dispute within Rule 3.4 is, in addition to and following the process in Parts C–G, **referred to arbitration** seated at the seat recorded in the Legal Profile. In default of a recorded seat, **the seat is London, England, and the arbitration agreement and the arbitration are governed by the law of England and Wales**. Settlement timing follows the signed Legal Policy election under Rule 6.3.

28.2 The tribunal in the arbitration is a **sole arbitrator, a natural person**, appointed by the Tribunal Entity as appointing body from its bench for the seat, having regard to (but not bound by) preferences stated in the order mandate. The Tribunal Entity shall appoint within **24 hours** of the E2 referral becoming ripe under Rule 28.3 and shall promptly notify the parties of the arbitrator's identity and electronic contact details.

28.3 An E2 referral is ripe upon the final Protocol Determination for the Case taking effect. To the fullest extent permitted by the law of the seat, the parties agree that the arbitration is commenced on the date of the notice of dispute under Rule 8. This agreement does not displace any mandatory commencement, notice or limitation requirement; the Tribunal Entity and parties shall take any additional step required to preserve a claim.

28.4 The parties appoint the protocol process of Parts C–G as the arbitration's **fact-finding and proposed-determination process**, and agree that the record assembled under it — the case object, the sealed evidence, each round's determinations and reasons, the proofs and the quality records — stands as the record in the arbitration without re-proof, subject to the arbitrator's powers in Rule 29, each party's reasonable opportunity to address that record, and any mandatory rule of the seat.

28.5 The arbitrator and the Tribunal Entity are not obliged to act unless the E2 fees per the published schedule are paid or secured.

### Rule 29 — Review of the record; adoption, variation or rejection

29.1 The Adopting Arbitrator shall personally review the record and shall exercise **independent judgment**. The arbitrator is not bound by the Protocol Determination.

29.2 On concluding the review, the arbitrator may:
(a) **adopt** the Protocol Determination, issuing it as the arbitrator's own reasoned award;
(b) **vary** it, adopting it in part and substituting the arbitrator's own determination in part, with reasons for each variance;
(c) **reject** it and determine the dispute afresh on the record, with reasons; or
(d) before doing any of the above, direct further written submissions or evidence commitments from the parties within a fixed period, direct a replay under Rule 22.5, or hold a remote hearing where the arbitrator considers it necessary for a fair award or applicable law requires it.

29.3 Whichever course is taken, the award is the arbitrator's own act and determination. The parties acknowledge that the arbitrator's mandate is adjudicative, not clerical, and agree not to contend that adoption of the Protocol Determination is of itself a failure by the arbitrator to discharge the mandate.

29.4 Under `implement_then_arbitrate`, where the award departs from an already-implemented Protocol Determination, the award shall give effect to the difference by orders against the parties (payment, transfer, or re-performance), the implementation under Rule 25 standing as a fact the award takes into account. Under `hold_pending_award`, the rail implements only after receipt of the conforming award instruction.

### Rule 30 — Award; seat; exclusions

30.1 The award shall be in writing, reasoned, dated, signed by the arbitrator (digital signature sufficing where the law of the seat permits), and shall state the seat. It shall be rendered so as to qualify for recognition and enforcement under the New York Convention wherever that Convention applies.

30.2 The award is final and binding on the parties, who undertake to carry it out without delay.

30.3 The arbitrator shall use best endeavours to render the award within **96 hours** of appointment, extendable under Rule 16.2.

30.4 **Where the seat is in England and Wales, appeal to the court on a point of law is excluded**: the parties exclude section 69 of the Arbitration Act 1996 (as amended). At every seat, the parties waive any right of appeal, review or recourse against the award to the fullest extent such waiver is permitted, without prejudice to Rule 30.5.

30.5 Nothing in these Rules excludes mandatory, non-waivable recourse at the seat (for England and Wales, challenges under sections 67 and 68 of the Arbitration Act 1996 (as amended)).

30.6 Confidentiality under Part I applies to the arbitration, save as disclosure is required to enforce or resist enforcement of the award.

---

## PART I — CONFIDENTIALITY

### Rule 31 — Confidentiality; publication of redacted determinations

31.1 The sealed evidence, the parties' submissions, the full reasons and the parties' identities (subject to Rule 32) are confidential to: the parties; the tribunals of each round; the Human Bench; the Adopting Arbitrator; and the Tribunal Entity's case administration, each under corresponding duties.

31.2 Except to the extent a signed `confidential_settlement` mode and disclosure policy require a commitments-only record, the following are public by design: the existence and procedural state of a Case as recorded in the settlement system; hash commitments; the ruling; and the verification material of Rule 23.2. Under a conforming confidential mode, only the commitments, receipts or other fields expressly authorized by that policy may be made public. The parties acknowledge the applicable boundary before signature and shall not commit material to a public layer that they wish to keep sealed.

31.3 Subject to applicable confidentiality, data-protection, trade-secret and sanctions law, the protocol may publish each final determination to the precedent registry in **redacted form**: reasoning tagged by issue and governing law with party-identifying and commercially sensitive content removed by selective disclosure. Agreement to these Rules supplies the parties' contractual consent but is not a substitute for any other lawful basis that may be required. A party may, within the challenge window, request additional redactions, which the Tribunal Entity shall adopt unless publication can lawfully proceed and the redactions would deprive the entry of precedential sense.

31.4 A party may disclose confidential material where required by law, regulation or court order; to its professional advisers, auditors and insurers under equivalent duties; and so far as necessary to implement, enforce or challenge a determination or award.

31.5 Settlement-network confidentiality is distinct from confidentiality of the evidence and proceedings under this Part and from anonymity under Rule 32. It is not a representation of absolute anonymity. The signed disclosure policy must identify the material classes visible to the parties, funds controller, Infrastructure Operators, private-network validators, bridge or solver operators, tribunal seats, human reviewers, auditors and public, as applicable; the purpose and basis of permitted disclosure; retention; and the form of any selective-disclosure receipt. Mandatory disclosure under Rule 31.4 prevails to the extent legally required, but must be limited where lawful and recorded where the applicable system permits.

### Rule 32 — Optional anonymity

32.1 Where the order mandate so provides, or the parties so agree, a party may participate anonymously as against the other party and the public. In `enterprise_legal` mode, its identity details and principal KYB reference are then submitted **confidentially to the tribunal alone** (and, on referral, to the Human Bench, the Adopting Arbitrator and the Tribunal Entity's case administration), and do not appear in the notice, the response, or any published form. In `wallet_native` or `rail_verified` mode, the public record may be limited to the applicable wallet, agent or opaque rail identifier.

32.2 A party must establish the identity assurance required by its signed mode to the tribunal's reasonable satisfaction. `enterprise_legal` mode requires identity of the principal and authority of the agent to bind it. `wallet_native` mode requires control of the signing key; `rail_verified` mode requires the authenticated rail reference and any proof the signed policy assigns to the rail. Anonymity under `enterprise_legal` mode is as between the parties and the public, never as against the tribunal.

32.3 The tribunal, the Tribunal Entity and the Adopting Arbitrator shall not disclose identity details submitted under Rule 32.1 except: where necessary for the fair resolution of the Case; where necessary for implementation or enforcement of a determination or award; for the protection of their own legitimate interests; or where required by law, regulation, sanctions compliance or court order.

---

## PART J — CODE AND LAW

### Rule 33 — Code deference; Material Adverse Exceptions

33.1 The parties agree that the outcomes produced by the deterministic operation of the settlement system and of the order mandate's machine checks are **deemed contractual performance** and are not, of themselves, breaches, mistakes or grounds of restitution — **except** on the occurrence of a Material Adverse Exception enumerated in the order mandate.

33.2 MAE events must be enumerated in the order mandate at signature. Typical enumerations include: exploitation of a defect in the relevant contract code; malfunction, halt or deep reorganisation of the underlying chain or settlement rail; failure or manipulation of an oracle or data feed on which a machine check depends; and compromise of an attested execution environment relied on for the Case. An event not enumerated is not an MAE for that transaction.

33.3 **A claim that an MAE has occurred is itself a dispute under these Rules**: it is commenced under Rule 8 as a distinct claim class, is assigned the tier of the value it affects, and is determined on evidence commitments specific to the alleged event. The party asserting the MAE bears the burden of establishing it by clear evidence, Rule 19.2 not applying to MAE claims.

33.4 Where an MAE is established, the tribunal selects among the Permitted Rulings so as to restore the parties, as nearly as the pre-committed branches allow, to the position the order mandate intended; at tiers E1 and above, any shortfall beyond the escrow may be pursued under the contract, and at tier E2 the Adopting Arbitrator may make orders in respect of it under Rule 29.4.

33.5 Pending determination of an MAE claim, the customer-controlled or customer-approved settlement system suspends implementation under Rule 25 of any determination affected by the alleged event, but only where the signed order mandate and Legal Policy pre-committed that MAE hold. The Protocol Operator has no credential or ad hoc power to freeze the affected funds.

---

## PART K — GENERAL

### Rule 34 — Liability and immunity

34.1 To the fullest extent permitted by applicable law, the parties agree that none of the following is contractually liable to a party or interested person for anything done or omitted in connection with a Case, a determination or an award, unless the act or omission is shown to have been fraudulent, dishonest or in bad faith: the Protocol Operator; the Tribunal Entity (including in its appointing-body function); any Infrastructure Operator in respect of its seat operations; any member of the Human Bench; and any Adopting Arbitrator. This Rule does not itself create statutory arbitral immunity or exclude an independently owed regulatory or statutory duty. Members of the Human Bench and Adopting Arbitrators additionally retain any immunity actually conferred by the law of the seat.

34.2 Subject to Rule 34.4, the aggregate liability of the Protocol Operator and the Tribunal Entity to all parties in respect of a Case is capped at the **greater of** the total fees paid to them for that Case and **USD [10,000]**, and in respect of all Cases in any 12-month period at **USD [250,000]**.

34.3 No person within Rule 34.1 is liable for loss of profit, loss of business, loss of data, or indirect or consequential loss, nor for the acts of the parties' own agents, nor for outcomes of the deterministic operation of code deferred to under Rule 33.1.

34.4 Nothing in these Rules excludes or limits liability that cannot lawfully be excluded or limited, including for fraud.

34.5 The persons identified in Rule 34.1 may rely on this Rule in their own right notwithstanding that they are not party to the order mandate, including under the Contracts (Rights of Third Parties) Act 1999 where the law of England and Wales applies.

### Rule 35 — Governing law of these Rules; amendment and versioning

35.1 These Rules, their incorporation and any dispute about their interpretation are governed by the **law of England and Wales**. This does not displace: (a) the governing law of the underlying contract, which is the law recorded in the Legal Profile; or (b) the law of the seat, which governs the arbitration under Part H.

35.2 In default of a recorded governing law in the Legal Profile, the underlying contract is governed by the law of England and Wales.

35.3 These Rules are **content-addressed**. Each published version has a rules identifier and a Rules Hash of its canonical UTF-8 text. **A Case is conducted under the version whose Rules Hash (or, failing a hash, whose identifier per Rule 4.3) is embedded in its signed order mandate or other signed incorporating instrument**, regardless of later amendment.

35.4 Amendment is by publication of a new version with a new identifier and Rules Hash, signed by the Tribunal Entity and recorded in the protocol's registry, together with a change log. No amendment applies to an order mandate signed before its publication.

35.5 If any provision of these Rules is invalid or unenforceable in a given application, it is severed to the minimum extent for that application, and the remainder continues in force.

---

*End of the Edict Dispute Resolution Rules v0.1 (`edict-drr-v0.1`). Signed
Legal Policies bind the SHA-256 hash of these exact UTF-8 bytes.*
