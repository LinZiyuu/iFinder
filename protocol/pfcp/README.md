# PFCP Data Layout

This folder stores PFCP knowledge used by `ifinder-sdk`.

## Structure

- `raw/Message/*.json`:
  Raw message definitions.
- `raw/IE/*.json`:
  Raw IE definitions.
- `generated/message_schemas.normalized.json`:
  Normalized message schema for Exploitation Agent.
- `generated/ie_catalog.normalized.json`:
  Normalized IE catalog used during schema generation.
- `procedure/*.json`:
  Procedure-level message flows used by Vetting Agent for
  code-specification cross-checking and recursive dependency expansion.

## Rule

Keep generated files under `generated/` only.
Do not place normalized artifacts under `raw/`.
