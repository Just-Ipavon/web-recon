# Technical documentation — webrecon

| | |
| --- | --- |
| System | webrecon 0.1.0 |
| Document type | Software Design Description (SDD) |
| Reference structure | ISO/IEC/IEEE 1016 |
| Diagram notation | UML 2.5, rendered in Mermaid |
| Last revised | 2026-07-27 |

## Index

| Document | Contents | Who it is for |
| --- | --- | --- |
| [01 — Architecture](01-architecture.md) | Context view, packages, data model, architectural decisions (ADRs), deployment, non-functional requirements | Anyone who needs to understand how the system is built, and why |
| [02 — Use cases](02-use-cases.md) | Actors, use case diagram, eight detailed specifications with main and alternative flows, operational scenarios, legitimacy constraints | Anyone who needs to understand what the system is for |
| [03 — Function reference](03-function-reference.md) | Every function, class and constant: behaviour, edge cases, error handling, covering tests | Anyone modifying or extending the code |
| [04 — Runtime behaviour](04-runtime-behaviour.md) | Sequence diagrams, lifecycle, concurrency model, error propagation, timing profile, verification strategy | Anyone who needs to understand what happens at runtime |

For installation and day-to-day usage, see the [project README](../README.md).

## Diagrams included

| UML type | Where | Subject |
| --- | --- | --- |
| Context diagram | 01 §1.2 | System and external actors |
| Package diagram | 01 §1.3 | Layers and the dependency rule |
| Class diagram | 01 §1.4 | Data model and infrastructure |
| Deployment diagram | 01 §1.6 | Execution nodes and protocols |
| Use case diagram | 02 §2.2 | Eight use cases with *include* and *extend* relationships |
| State diagram | 03 §3.7, 04 §4.6 | `Throttle` states and the scan lifecycle |
| Activity diagram | 03 §3.8, §3.15 | Subdomain enumeration, CLI flow |
| Sequence diagram | 04 §4.2–4.5, §4.7 | Overall scan, enumeration, HTTP probe, TLS inspection, throttling |

The diagrams are written in Mermaid and rendered natively by GitHub, GitLab and
most Markdown editors. They need no external tooling and no image export: the
diagram source is versioned alongside the prose, so a code change and its
diagram update land in the same commit.

## Conventions

- Code references are relative links to the source file, so they stay navigable
  both on GitHub and locally.
- Architectural decisions are numbered `ADR-nn` and cited by the documents that
  depend on them.
- Use cases are numbered `UC-nn`; the traceability matrix in
  [02 §2.3](02-use-cases.md#23-traceability-matrix) links each one to the module
  that realises it and the tests that verify it.

## Maintenance

This documentation describes the actual behaviour of the code at the revision
stated above, not a design intention. Any change that alters a function
signature, an error flow or an exit code requires the corresponding document to
be updated in the same commit.
