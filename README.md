# iFinder

**iFinder** is an LLM-driven multi-agent framework for systematically detecting *implicit trust errors* (iTrues) in cellular core network implementations. By distilling vulnerability patterns from historical flaws, iFinder discovers, verifies, and exploits previously unknown vulnerabilities across open-source core network software.

This repository contains the artifact accompanying the paper:

> *Understanding Implicit Trust Errors in Core Carrier Networks through Multi-Agent Flaw Discovery and Analysis*

## Approach

iFinder decomposes end-to-end vulnerability research into three specialized agents, each augmented with 3GPP specification knowledge to suppress LLM hallucinations:

- **Discovery Agent.** Detects iTrue candidates via semantic backward analysis. The agent first locates code sites where protocol-controlled IEs are used in pattern-matched dangerous operations, then walks backward along caller chains to reconstruct the execution context from the protocol message handler to the dangerous operation, and finally checks whether the required validations (protocol-syntax, protocol-semantics, and resource-availability) are missing along the path.

- **Vetting Agent.** Conducts code-specification cross-checking to reduce false positives. The agent leverages 3GPP specifications to expand the analysis context via a three-step approach: locating the candidate's triggering message in the specification-defined procedure, mapping all prerequisite messages back to their code handlers, and reexamining iTrue candidates under the expanded code context to determine whether security checks in preceding states make exploitation infeasible.

- **Exploitation Agent.** Automatically generates a PoC for each iTrue candidate via a three-step workflow. First, the agent derives an explicit attack vector and instantiates protocol-compliant messages using the extracted message schemas, then generates the PoC strictly from these intermediate artifacts. Second, it performs pre-execution checks (e.g., compilability and consistency with the attack vector) to catch malformed or drifting PoCs. Finally, when a well-formed PoC still fails due to implicit runtime constraints, the agent invokes a *feedback-aware refinement* loop — analyzing runtime logs, updating the PoC to satisfy missing constraints, and re-executing until the flaw is triggered or the testing budget is exhausted.

## Usage

```bash
# Stage 1: Discovery
PYTHONPATH=ifinder-sdk/src python -m ifinder_sdk.tools.discovery_claude_runner \
  --pattern PA1 --scope scope_open5gs.json --target open5gs \
  --coverage-map protocol/pfcp/coverage_map.json \
  --output-dir outputs/discovery_results

# Stage 2: Vetting
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
