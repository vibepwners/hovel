# RFC-SGM-0001: Specification Graph Method

- Status: Draft
- Version: 0.1.0
- Authors: Project Team
- Last Updated: 2026-03-21
- Intended Audience: Product, Architecture, Engineering, QA, AI-assisted development systems

## 1. Abstract

This document defines the **Specification Graph Method (SGM)**, a method for representing software intent as a version-controlled graph of formalized artifacts. Under this method, the canonical durable representation of a software system is not the source tree alone, but a linked corpus of vision artifacts, requirements, design decisions, behavioral models, verification artifacts, and implementation mappings.

The purpose of SGM is to reduce cognitive debt, preserve rationale, improve review quality, support AI-assisted implementation, and enable reconstruction of system intent across refactors, rewrites, team turnover, and model context loss.

## 2. Status of This Memo

This memo defines a process and repository convention. Distribution of this memo is unlimited.

This document uses the key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## 3. Motivation

AI-assisted software development lowers the cost of implementation but often increases the cost of long-horizon maintenance when intent is not durably captured. Systems developed through fragmented prompts, ad hoc prose, and implementation-first iteration accumulate **cognitive debt**: the future re-entry cost created when implementation detail outpaces durable articulation of purpose, constraints, and rationale.

Traditional source control versions code well, but it does not by itself version intent. Large markdown corpora frequently become a heap rather than a model. Diagram collections frequently become illustrations rather than governing artifacts. Tests often verify behavior without explaining why that behavior exists. Architectural rationale is commonly lost.

SGM addresses this by treating software intent as a directed graph of artifacts with stable identifiers and typed traceability edges.

## 4. Goals

SGM has the following goals:

1. Preserve durable software intent independently of transient model or human memory.
2. Make software behavior, rationale, and structure reviewable before or alongside implementation.
3. Support decomposition of large systems into linked artifacts.
4. Improve traceability from product purpose to code and tests.
5. Support AI systems by providing high-signal, queryable context.
6. Permit selective formalization of high-risk or high-complexity behaviors.
7. Remain practical for ordinary engineering teams using standard version control.

## 5. Non-Goals

SGM does not attempt to:

1. Replace implementation with diagrams.
2. Require theorem proving or full formal verification for the entire system.
3. Freeze design before discovery.
4. Mandate a specific programming language, architecture style, or testing framework.
5. Require all code to be generated from specification artifacts.
6. Turn software development into document bureaucracy.

## 6. Terminology

### 6.1 Specification Graph

A **Specification Graph** is a version-controlled directed graph whose nodes are typed software-specification artifacts and whose edges express typed relationships such as derivation, refinement, modeling, verification, and implementation mapping.

### 6.2 Artifact

An **artifact** is a durable, versioned unit of software intent or realization metadata, such as a vision statement, requirement, design decision, state model, sequence diagram, verification spec, or implementation mapping.

### 6.3 Cognitive Debt

**Cognitive debt** is the future re-entry cost created when implementation detail outpaces durable articulation of product intent, constraints, rationale, and behavior.

### 6.4 Eternal Software

**Eternal software** is software whose essential intent can survive author absence, team turnover, model context resets, implementation rewrites, language changes, and large refactors because that intent has been durably externalized.

### 6.5 Traceability Edge

A **traceability edge** is a typed relationship between two artifacts in the graph.

## 7. Architectural Thesis

A software system using SGM SHALL treat the Specification Graph as the canonical durable representation of system intent.

Source code SHALL be treated as an implementation artifact derived from the graph, even when code is authored manually. The graph is normative with respect to product purpose, requirement identity, rationale, behavioral intent, and verification intent. The implementation is normative with respect to exact executable behavior at runtime.

When graph artifacts and implementation diverge, the divergence MUST be resolved through review.

## 8. Canonical Derivation Flow

The canonical derivation flow is:

**Vision -> Requirements -> Decisions -> Design Models -> Verification -> Code**

This flow is normative at the level of intent, even if implementation work occurs iteratively.

### 8.1 Vision

Vision artifacts define why the system exists, what problems it solves, what success means, and what is explicitly out of scope.

### 8.2 Requirements

Requirement artifacts define externally meaningful capabilities, constraints, and behaviors.

### 8.3 Decisions

Decision artifacts define major architectural or product tradeoffs, alternatives considered, and rationale.

### 8.4 Design Models

Design model artifacts define structure, runtime interactions, state transitions, interfaces, boundaries, and topology.

### 8.5 Verification

Verification artifacts define how conformance to requirements will be demonstrated.

### 8.6 Code

Code realizes the system behavior described by upstream artifacts.

## 9. Artifact Taxonomy

The following artifact types are defined by this RFC.

### 9.1 Vision Artifacts

Vision artifacts capture product mission, user value, strategic constraints, success criteria, and non-goals.

A vision artifact SHOULD answer:
- Why does this system exist?
- For whom does it exist?
- What problem is being solved?
- What will not be solved?

Examples:
- product vision
- goals and success metrics
- scope and non-goals
- product principles

### 9.2 Requirement Artifacts

Requirement artifacts define normative statements about what the system SHALL do or SHALL NOT do.

Requirements MAY cover:
- product behavior
- operational behavior
- performance constraints
- security constraints
- compliance constraints
- interface guarantees
- recovery guarantees

Each requirement artifact MUST have:
- a stable ID
- a title
- a normative statement
- rationale or source context
- acceptance criteria or verification linkage

### 9.3 Decision Artifacts

Decision artifacts record why major choices were made.

A decision artifact MUST include:
- problem being decided
- options considered
- selected option
- rationale
- consequences
- supersession status, if applicable

Decision artifacts SHOULD be written as ADRs.

### 9.4 Design Model Artifacts

Design model artifacts describe system behavior or structure.

They MAY include:
- component diagrams
- context diagrams
- deployment diagrams
- domain models
- sequence diagrams
- state machines
- interface models
- data schemas

Design model artifacts SHOULD be text-first when feasible.

### 9.5 Verification Artifacts

Verification artifacts define how requirements are checked.

They MAY include:
- acceptance test specifications
- contract tests
- property tests
- invariants
- scenario tests
- quality gates
- formal models for risky behavior

Each important requirement SHOULD map to at least one verification artifact.

### 9.6 Implementation Mapping Artifacts

Implementation mapping artifacts connect specification nodes to realized implementation locations.

They MAY include:
- module mappings
- path mappings
- ownership mappings
- requirement-to-test matrices
- requirement-to-service mappings

## 10. Artifact Identity

Every durable artifact MUST have a stable identifier.

The following prefix conventions are RECOMMENDED:

- `VIS-###` for vision artifacts
- `REQ-###` for requirements
- `ADR-###` for decisions
- `MOD-###` for general design models
- `SEQ-###` for sequence models
- `STATE-###` for state models
- `DEP-###` for deployment models
- `TEST-###` for verification artifacts
- `MAP-###` for implementation mappings

Artifact identifiers:
- MUST be unique within the repository
- MUST remain stable after creation
- MUST NOT be repurposed for unrelated content
- MAY have titles changed over time

## 11. Graph Edge Types

The Specification Graph MUST support typed relationships. The following edge types are RECOMMENDED:

- `derives_from`
- `refines`
- `constrains`
- `decided_by`
- `modeled_by`
- `verified_by`
- `implemented_by`
- `supersedes`
- `related_to`

### 11.1 Edge Semantics

- `derives_from`: artifact originates from broader intent or a higher-level artifact
- `refines`: artifact provides a more specific or decomposed form of another
- `constrains`: artifact imposes rules or limits on another
- `decided_by`: artifact is governed by a decision artifact
- `modeled_by`: artifact behavior or structure is represented by a design model artifact
- `verified_by`: artifact is checked by a verification artifact
- `implemented_by`: artifact is realized in designated code locations
- `supersedes`: artifact replaces an older one
- `related_to`: non-normative relationship with explanatory value

## 12. Normative Rules

The following rules are mandatory unless explicitly exempted by project policy.

### Rule 1: Intent Linkage

Every requirement artifact MUST derive from at least one higher-level artifact, such as a vision artifact or a broader requirement.

### Rule 2: Stable Decision Capture

Every major architectural or product choice with long-term impact MUST be captured in a decision artifact.

### Rule 3: Explicit Modeling of Risk

High-risk, stateful, concurrent, security-sensitive, or lifecycle-heavy behavior SHOULD be modeled explicitly.

### Rule 4: Verification Linkage

Every important requirement MUST have at least one verification linkage.

### Rule 5: Implementation Traceability

Every major implemented capability SHOULD map back to at least one requirement artifact.

### Rule 6: No Feature Exists Only in Code

No major user-visible feature or major architectural subsystem SHOULD exist only in implementation without a corresponding requirement, decision, model, or mapping artifact.

### Rule 7: Change Coherency

A change that materially alters system behavior, architecture, or guarantees MUST update corresponding graph artifacts in the same change set or an explicitly linked precursor change set.

### Rule 8: Supersession Discipline

When an artifact is replaced, the replacement MUST declare supersession and the old artifact MUST remain historically identifiable.

### Rule 9: Reviewable Format

Primary artifacts MUST be stored in reviewable, version-control-friendly formats.

### Rule 10: Human Interpretability

Artifacts MUST remain interpretable by an informed engineer without requiring proprietary tooling or hidden state.

## 13. Representation Formats

### 13.1 Prose Formats

Markdown is RECOMMENDED for:
- vision artifacts
- requirement artifacts
- decision artifacts
- verification specs
- policy notes

### 13.2 Diagram Formats

Text-based diagrams are RECOMMENDED.

Preferred:
- PlantUML

Optional:
- Mermaid, for lighter-weight cases
- draw.io or similar, only when accompanied by stable source and acceptable review conventions

### 13.3 Interface Formats

Machine-readable schemas are RECOMMENDED where applicable:
- OpenAPI
- AsyncAPI
- JSON Schema
- Protocol Buffers
- GraphQL SDL

### 13.4 Stronger Formal Methods

Selective stronger formalism MAY be used for high-risk behaviors:
- TLA+ for concurrency, distributed protocols, and state machines
- Alloy for relational constraints and model consistency
- OCL-like constraints for model invariants
- other proof or verification systems as appropriate

## 14. Role of UML

UML is a valid design-model layer within SGM but is not sufficient as the complete specification system.

UML is especially appropriate for:
- sequence models
- class or domain models
- state machines
- component diagrams
- deployment views

UML alone does not adequately express:
- product mission
- non-goals
- rationale
- requirement acceptance criteria
- implementation mappings
- cross-artifact traceability semantics

Projects using UML MUST embed UML artifacts into the broader Specification Graph rather than treating UML as the sole source of intent.

## 15. Repository Layout

The following repository layout is RECOMMENDED:

```text
spec/
  vision/
    VIS-001-product-vision.md
    VIS-002-scope-and-non-goals.md

  requirements/
    REQ-001-resumable-upload.md
    REQ-002-job-processing.md
    REQ-003-review-authorization.md

  decisions/
    ADR-001-storage-strategy.md
    ADR-002-processing-model.md

  models/
    MOD-001-system-context.puml
    MOD-002-domain-model.puml
    SEQ-001-upload-flow.puml
    STATE-001-job-lifecycle.puml
    DEP-001-runtime-topology.puml

  verification/
    TEST-001-upload-acceptance.md
    TEST-002-job-retry-idempotency.md

  traceability/
    graph.yaml
    schema.yaml
```

Alternative layouts MAY be used provided the project maintains stable IDs and reviewable traceability.

## 16. Artifact Schemas

### 16.1 Requirement Artifact Template

```markdown
# REQ-001: Resumable Upload

## Status
Accepted

## Statement
The system SHALL support resumable upload for files larger than the configured single-request threshold.

## Rationale
Large uploads are vulnerable to interruption and MUST be restartable without full retransmission.

## Derives From
- VIS-001

## Acceptance Criteria
- Interrupted uploads can resume from the last committed chunk.
- Duplicate chunk submission does not corrupt file state.
- Partial upload state expires according to retention policy.

## Related Decisions
- ADR-001

## Modeled By
- SEQ-001
- STATE-001

## Verified By
- TEST-001
- TEST-002

## Implemented By
- services/files/
- services/uploads/
```

### 16.2 Decision Artifact Template

```markdown
# ADR-001: Use Object Storage for Blob Data

## Status
Accepted

## Context
The system stores large binary objects and must support durability, resumability, and horizontal scaling.

## Decision
The system will store blob payloads in object storage rather than local filesystem storage on application nodes.

## Alternatives Considered
- Local disk per node
- Network filesystem
- Database BLOB columns

## Rationale
Object storage provides better durability semantics, separation of concerns, and scaling properties.

## Consequences
- Upload workflows must support multipart object commit semantics.
- Local development requires an object-storage-compatible service.
- Metadata and blob payloads become separately managed.

## Related Requirements
- REQ-001
- REQ-002

## Supersedes
- None
```

### 16.3 Verification Artifact Template

```markdown
# TEST-002: Job Retry Idempotency

## Status
Accepted

## Verifies
- REQ-002

## Goal
Demonstrate that retrying a failed job does not create duplicate committed outputs.

## Preconditions
- A job exists in retriable failed state.
- Output persistence target is reachable.

## Procedure
1. Trigger retry for the failed job.
2. Simulate transient failure after side-effect preparation but before final commit.
3. Retry again.
4. Inspect resulting outputs and job state.

## Expected Results
- At most one committed output exists.
- Job state converges to succeeded or terminal failed state.
- Duplicate retry does not create duplicate user-visible side effects.
```

## 17. Traceability File

Projects using SGM SHOULD maintain a machine-readable traceability file.

A YAML representation is RECOMMENDED.

Example:

```yaml
VIS-001:
  type: vision
  title: Product Vision

REQ-001:
  type: requirement
  title: Resumable Upload
  derives_from: [VIS-001]
  decided_by: [ADR-001]
  modeled_by: [SEQ-001, STATE-001]
  verified_by: [TEST-001, TEST-002]
  implemented_by:
    - services/files/*
    - services/uploads/*

ADR-001:
  type: decision
  title: Use Object Storage for Blob Data
  related_to: [REQ-001]

SEQ-001:
  type: model
  title: Upload Flow

STATE-001:
  type: state-model
  title: Upload Lifecycle

TEST-002:
  type: verification
  title: Job Retry Idempotency
  verifies: [REQ-002]
```

Projects MAY generate this file automatically from front matter or inline references, but the resulting graph MUST remain reviewable.

## 18. Change Management

### 18.1 Behavior Changes

A pull request that materially changes externally meaningful behavior SHOULD update:
- one or more requirement artifacts
- verification artifacts
- implementation mappings, if relevant

### 18.2 Architectural Changes

A pull request that materially changes architecture SHOULD update:
- decision artifacts
- relevant design models
- implementation mappings

### 18.3 Superseded Behavior

When replacing requirements or design intent:
- old artifacts MUST remain identifiable
- replacement artifacts MUST declare supersession
- trace links SHOULD remain historically valid

### 18.4 Implementation Discovery

When implementation work reveals that a specification artifact is infeasible, incomplete, or incorrect, the finding MUST flow back into the specification through a formal amendment rather than silent divergence.

The RECOMMENDED process is:

1. The implementer documents the discovery: what was attempted, what failed or proved infeasible, and why.
2. The affected specification artifact is updated or superseded to reflect the corrected understanding.
3. Dependent artifacts (decisions, models, verification) are updated as needed to maintain graph coherency.
4. The specification amendment and the implementation change MAY land in the same change set or in explicitly linked change sets.

Implementation discoveries are a normal part of the development process, not a failure of specification. The purpose of this feedback loop is to ensure the graph remains an accurate representation of intent rather than an aspirational document that silently diverges from reality.

## 19. Review Process

Projects using SGM SHOULD review changes at the specification layer, not only at the implementation layer.

The review sequence is RECOMMENDED as:

1. Product review
2. Design review
3. Verification review
4. Implementation review

### 19.1 Product Review

Confirms the change solves the right problem.

### 19.2 Design Review

Confirms the selected design is coherent and appropriately justified.

### 19.3 Verification Review

Confirms correctness criteria are explicit and testable.

### 19.4 Implementation Review

Confirms the code realizes the declared intent.

## 20. AI-Assisted Development Requirements

Projects using AI-assisted implementation SHOULD use the Specification Graph as the primary context source for non-trivial changes.

The following AI workflow is RECOMMENDED:

1. Read the relevant graph neighborhood.
2. Summarize applicable vision, requirements, decisions, and models.
3. Propose specification deltas before major implementation.
4. Update verification artifacts.
5. Implement code.
6. Report trace links in the resulting change.

AI agents SHOULD prefer graph-linked artifacts over ad hoc repo scanning when determining intent.

## 21. Selective Formalization Policy

Projects SHOULD selectively formalize the highest-risk parts of the system rather than attempting full-project mathematical formalization.

Candidates for stronger formalization include:
- distributed protocols
- retry semantics
- idempotency guarantees
- state machines with complex transitions
- security authorization rules
- financial ledgers
- concurrency-sensitive schedulers

A project MAY attach stronger models, such as TLA+ or Alloy, to requirement or design nodes for these cases.

## 22. Conformance Levels

### 22.1 Level 0: Ad Hoc

The project has scattered docs and no stable traceability discipline.

### 22.2 Level 1: Minimal SGM

The project has:
- at least one vision artifact
- numbered requirement artifacts
- ADRs for major decisions
- key design models
- requirement-linked verification artifacts
- a traceability map

### 22.3 Level 2: Managed SGM

The project additionally has:
- enforced artifact schemas
- CI validation of traceability
- requirement-linked tests
- supersession discipline
- pull request review expectations tied to graph changes

### 22.4 Level 3: Formalized SGM

The project additionally has:
- machine-checked graph consistency
- automated generation of trace views
- stronger formal models for risky behavior
- bidirectional linkage between graph and code metadata

## 23. Security Considerations

Poorly maintained specifications can create false confidence. A stale graph is dangerous because it appears authoritative while being wrong.

Therefore:
- graph artifacts MUST be updated alongside major changes
- security-sensitive requirements SHOULD have explicit verification linkages
- decision artifacts for trust boundaries, authentication, authorization, cryptography, and data retention SHOULD be mandatory
- projects SHOULD flag orphaned requirements and unverified security requirements in CI

## 24. Operational Considerations

SGM introduces process overhead. Projects SHOULD keep artifacts small, linked, and purpose-specific rather than writing monolithic documents.

To avoid bureaucracy:
- artifacts SHOULD answer one primary question
- diagrams SHOULD be narrow in scope
- requirement count SHOULD favor decomposition over giant omnibus specs
- decision artifacts SHOULD capture only significant choices
- stronger formal methods SHOULD be reserved for risky cases

## 25. Migration Strategy

Existing implementation-first projects MAY adopt SGM incrementally.

The RECOMMENDED order is:

1. Write one vision artifact.
2. Identify major requirements and assign IDs.
3. Capture major architectural decisions as ADRs.
4. Create key sequence/state/component models.
5. Link important tests to requirement IDs.
6. Create a traceability file.
7. Expand coverage over time.

Projects SHOULD NOT attempt to reverse-document every implementation detail. They SHOULD prioritize active subsystems and risky behavior.

## 26. Example Minimal Adoption Policy

A project claiming SGM adoption at minimum SHALL maintain:
- `VIS-001`
- one or more `REQ-*` artifacts
- one or more `ADR-*` artifacts for major choices
- at least one key behavioral model
- at least one `TEST-*` artifact linked to a requirement
- one graph mapping file

## 27. Rationale Summary

SGM exists because:
- code is not sufficient as durable intent memory
- markdown without structure does not scale
- UML without surrounding semantics is insufficient
- tests without rationale are incomplete
- AI implementation benefits from high-signal, structured context
- teams need a reviewable system memory that survives time

## 28. IANA Considerations

This document has no IANA actions.

## 29. References

### 29.1 Normative References

- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words

### 29.2 Informative References

- Architecture Decision Records
- UML and PlantUML
- TLA+
- Alloy
- OpenAPI
- AsyncAPI
- JSON Schema

## 30. Final Normative Statement

A software project conforming to this RFC SHALL maintain a version-controlled Specification Graph whose nodes represent product intent, requirements, design rationale, behavioral models, verification artifacts, and implementation mappings. This graph SHALL serve as the canonical durable representation of the system’s intent, and major implementation changes SHALL remain traceable to it.
