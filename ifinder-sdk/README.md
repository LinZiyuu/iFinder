# ifinder-sdk

`ifinder-sdk` 是 iFinder 的 SDK 化实现，提供 Discovery / Vetting / Exploitation 三阶段工具和编排入口。

## 目录约定

默认按以下协议数据布局读取：

- `../pattern/*.json`
- `../protocol/pfcp/procedure/*.json`
- `../protocol/pfcp/generated/message_schemas.normalized.json`

## 快速开始

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

## 主要 API

- `ifinder_sdk.client.IFinderClient`
  - `phase1_discover(...)`
  - `phase2_vet(...)`
  - `phase3_exploit(...)`
  - `run_pipeline(...)`

- `ifinder_sdk.tools`
  - `discover_itrue_candidates(...)`
  - `vet_discovery_result(...)`
  - `exploit_candidate(...)`

## 测试

```bash
pytest -q
```
