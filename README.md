# iFinder

**iFinder** is an LLM-driven multi-agent framework for systematically detecting *implicit trust errors* (iTrues) in cellular core network implementations. By distilling vulnerability patterns from historical flaws, iFinder discovers, verifies, and exploits previously unknown vulnerabilities across open-source core network software.

This repository contains the artifact accompanying the paper:

> *Understanding Implicit Trust Errors in Core Carrier Networks through Multi-Agent Flaw Discovery and Analysis*

## Approach

iFinder decomposes end-to-end vulnerability research into three specialized agents, each augmented with 3GPP specification knowledge to suppress LLM hallucinations:

- **Discovery Agent.** Performs pattern-guided code auditing with taint-style reasoning. A *coverage map* derived from 3GPP specifications enumerates the audit space as ⟨Message, IE⟩ pairs, enabling systematic and measurable code review. For each audit unit, the agent traces attacker-controlled protocol inputs (sources) through the implementation and flags cases where they reach security-sensitive operations (sinks) without adequate sanitization.

- **Verification Agent.** Conducts specification-grounded cross-checking to reduce false positives. Using *procedure sequences* extracted from 3GPP specifications, the agent localizes prerequisite protocol stages and evaluates each candidate along five dimensions: controllability, reachability, defense inadequacy, state feasibility, and security impact.

- **Exploitation Agent.** Generates proof-of-concept (PoC) exploits via feedback-aware refinement. The agent derives attack vectors from *message schemas* and *procedure sequences*, constructs protocol-compliant messages, executes the PoC against a testbed, analyzes runtime logs, and iteratively refines until the vulnerability is confirmed or the retry budget is exhausted.

## Usage

```bash
# Stage 1: Discovery
PYTHONPATH=ifinder-sdk/src python -m ifinder_sdk.tools.discovery_claude_runner \
  --pattern PA1 --scope scope_open5gs.json --target open5gs \
  --coverage-map protocol/pfcp/coverage_map.json \
  --output-dir outputs/discovery_results

# Stage 2: Verification
PYTHONPATH=ifinder-sdk/src python -c "
from ifinder_sdk.tools.vetting import vet_discovery_result
import json
discovery = json.load(open('outputs/discovery_results/<DISCOVERY_RESULT>.json'))
result = vet_discovery_result(
    discovery,
    procedure_dir='protocol/pfcp/procedure',
    target_codebase='target/open5gs',
    scan_dirs=['lib/pfcp/', 'src/smf/', 'src/upf/'],
)
json.dump(result.model_dump(mode='json'), open('outputs/vetting_results/result.json','w'), indent=2)
"

# Stage 3: Exploitation
PYTHONPATH=ifinder-sdk/src python -c "
from ifinder_sdk import IFinderClient
import json
client = IFinderClient()
discovery = json.load(open('outputs/discovery_results/<DISCOVERY_RESULT>.json'))
vetting = json.load(open('outputs/vetting_results/result.json'))
results = client.phase3_exploit(
    discovery=discovery,
    vetting=vetting,
    output_root='outputs/exploitation_results',
    docker_container='<CONTAINER_NAME>',  # or target_ip='<TARGET_IP>'
)
"
```

Full pipeline (programmatic):

```python
from ifinder_sdk import IFinderClient

client = IFinderClient()
artifact = client.run_pipeline(
    pattern="PA1.json",
    target_codebase="target/open5gs",
    scan_dirs=["lib/pfcp/", "src/smf/", "src/upf/"],
    output_root="outputs",
    docker_container="<CONTAINER_NAME>",  # or target_ip="<TARGET_IP>"
)
```
