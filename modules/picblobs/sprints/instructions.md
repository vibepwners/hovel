# Sprint Documentation

## Purpose

Sprint documents capture what was worked on during a sprint, what decisions were made or revised, and how the specification graph evolved. They serve as a changelog at the intent level — not just what code changed, but what understanding changed.

## File Convention

Each sprint gets its own file in this directory:

```
sprints/
  instructions.md        # this file
  SPRINT-001.md
  SPRINT-002.md
  ...
```

Sprint numbers are sequential and zero-padded to three digits.

## Sprint Document Template

```markdown
# SPRINT-NNN: <Title>

## Period
YYYY-MM-DD to YYYY-MM-DD

## Goal
One or two sentences describing the sprint objective.

## Work Completed

Bulleted summary of what was accomplished. Reference artifact IDs where applicable.

- Implemented X (REQ-001, REQ-003)
- Designed Y (MOD-002)
- Resolved issue Z

## Work Not Completed

Anything planned but deferred, with a brief reason.

- Deferred X due to Y

## ADR Updates

### New Decisions

List any new ADRs created during this sprint.

- **ADR-NNN: <Title>** — <one-line summary of what was decided and why>

### Amended Decisions

List any existing ADRs that were updated. Describe what changed and why.

- **ADR-NNN: <Title>** — <what changed>. Reason: <why>.

### Superseded Decisions

List any ADRs that were replaced. Reference the replacement.

- **ADR-NNN** superseded by **ADR-NNN** — <why the original decision no longer holds>

## Other Spec Changes

Note any non-ADR specification artifacts that were created, updated, or superseded during this sprint (requirements, models, verification specs, vision).

- **REQ-NNN: <Title>** — created / updated / superseded. <brief context>
- **MOD-NNN: <Title>** — created / updated. <brief context>
- **TEST-NNN: <Title>** — created / updated. <brief context>

## Implementation Discoveries

Findings from implementation that fed back into the specification (per SGM Section 18.4). If none, omit this section.

- <what was attempted, what was learned, what spec artifact was amended>

## Notes

Any other context relevant to understanding this sprint's outcome.
```

## Rules

1. Every sprint document MUST reference artifact IDs (REQ-NNN, ADR-NNN, etc.) when describing spec-related work.
2. ADR changes MUST be reflected in both the sprint document and the actual ADR files in `spec/decisions/`. The sprint document summarizes the change; the ADR file is the source of truth.
3. New or amended ADRs MUST follow the template in `spec/decisions/` and maintain correct status fields (Accepted, Amended, Superseded).
4. If a sprint produces no ADR changes, the ADR Updates section SHOULD still be present with "None" under each subsection.
5. The sprint document is a record, not a plan. Write it at the end of the sprint to describe what actually happened.
