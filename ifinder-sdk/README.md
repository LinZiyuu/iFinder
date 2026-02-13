# ifinder-sdk

`ifinder-sdk` is the SDK implementation of iFinder, providing Discovery / Vetting / Exploitation three-stage tools and orchestration entry points.

## Directory Conventions

Default protocol data layout:

- `../pattern/*.json`
- `../protocol/pfcp/procedure/*.json`
- `../protocol/pfcp/generated/message_schemas.normalized.json`

## Quick Start

```python
from ifinder_sdk import IFinderClient

client = IFinderClient()
artifact = client.run_pipeline(
    pattern="PA1.json",
    target_codebase="/path/to/open5gs",
    scan_dirs=["src"],
    output_root="outputs",
    target_version="v2.7.6",
)
```

## API

- `ifinder_sdk.client.IFinderClient`
  - `phase1_discover(...)`
  - `phase2_vet(...)`
  - `phase3_exploit(...)`
  - `run_pipeline(...)`

- `ifinder_sdk.tools`
  - `discover_itrue_candidates(...)`
  - `vet_discovery_result(...)`
  - `exploit_candidate(...)`

## Tests

```bash
pytest -q
```
