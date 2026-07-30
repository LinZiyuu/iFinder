<!--
## How to Run the CI
-->

<!--
The CI pipeline normally runs the full suite of builds and tests. You can control whether it runs or is skipped using MR labels:
No label → Full suite runs.
CI or RETRIGGER-CI → Forces full suite run, even if other skip labels are present.
documentation → Skips the full suite. Useful for MRs that only update docs.
-->


## Network Function Source Configuration


```json
{
  "NRF": ["develop", "main"],
  "UPF": ["develop", "main"],
  "AUSF": ["develop", "main"],
  "UDR": ["develop", "main"],
  "AMF": ["develop", "develop"],
  "UDM": ["sidf-non-null-schemes-test", "4586ca681184d9b42ca1e7f9ded6466acf4f526a"],
  "SMF": ["develop", "b5042f5f"]
}
```

<!--
Use the JSON block above to specify the network function branch or commit and the corresponding common-src branch or commit.

- The key is the NF name.
- The first value is the branch or commit ID of the network function.
- The second value is the branch or commit ID of the submodule common-src.

For merge requests:
- If a network function commit or branch is missing, the pipeline will fail.
- If a common-src branch or commit is missing for a network function, the pipeline uses the source branch commit ID of this merge request.

Note: At the moment, AMF, UDM, and SMF use different common-src commit IDs.
It is strongly advisable to put all NF commits/branches if changed and the common-src commits/branches.
-->

## Impacted Network Functions from this MR

<!--
List the network functions impacted by this MR.
Include feature branches and/or related merge requests when applicable.
-->

- UDM
- NRF
- UPF
- AUSF
- UDR
- AMF (scheme_a_b_test, MR !419)
- SMF
