# CI Pipeline Documentation for `OAI-CN5G-COMMON-SRC`

> SPDX-License-Identifier: LicenseRef-CSSL-1.0

## 1. Overview

The CI pipeline [OAI-CN5G-COMMON-SRC](https://jenkins-oai.eurecom.fr/view/5G%20Core%20Network/job/OAI-CN5G-Common-Src/) determines:

* Which branch or commit of each NF to use
* Which `common-src` branch or commit to associate with each NF

The pipeline is triggered in the following cases:

* A Merge Request targeting the `develop` or `main` branch.
* A Push to the `develop` or `main` branch

The behavior differs depending on whether the trigger is a **Merge Request (MR)** or a **Push event**.

## 2. Network Functions Covered by CI

The CI pipeline currently operates on the following seven Network Functions:

```groovy
["NRF", "AUSF", "UPF", "UDR", "AMF", "UDM", "SMF"]
```

This list is defined in the Jenkins script.
All seven NFs are included in every CI execution, and any missing NFs are automatically added with some default configuration.

## 3. Merge Request (MR) Workflow

### 3.1 JSON-Based Configuration

For Merge Requests, the CI pipeline parses a JSON block included in the MR description.

This JSON block defines:

* The branch or commit of each Network Function
* The branch or commit of the `common-src` submodule

The JSON block can be updated via the [Merge Request template](../.gitlab/merge_request_templates/description.md).

### 3.2 Example JSON Configuration

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

Each entry follows this format:

```json
"NF_NAME": ["nf_branch_or_commit", "common_src_branch_or_commit"]
```

* **First value** – Branch or commit of the Network Function repository
* **Second value** – Branch or commit of the `common-src` submodule

### 3.3 Handling Missing Network Functions in MR

The pipeline defines:

```groovy
allRequiredNFs = ["NRF", "AUSF", "UPF", "UDR", "AMF", "UDM", "SMF"]
```

If a Network Function is not present in the JSON block:

```groovy
if (!nfList.contains(reqNF)) {
  nfList.add(reqNF)
  nfCommitList.add("develop")
}
```

If an NF is omitted from the JSON:

* It is automatically added.
* Its NF branch defaults to `develop`.
* Its `common-src` commit defaults to the current MR commit of `common-src`.

Even if the MR JSON block omits an NF:

* It will still be built.
* It will use:

  * NF branch: `develop`
  * `common-src`: current MR commit

## 4. Push Event Workflow

### 4.1 Network Function Branch

For Push events:

* All Network Functions use the `develop` branch.
* Network Function changes must be merged into `develop` before pushing `common-src`. If NFs are not yet pushed to develop, common-src would not have a valid reference commit for those NFs.

Defined as:

```groovy
nfList = ["NRF", "AUSF", "UPF", "UDR", "AMF", "UDM", "SMF"]
```

All seven NFs are always included.

### 4.2 Default `common-src` Commit (Push)

By default:

* The `common-src` commit used is the current commit that triggered the pipeline.

This corresponds to the short SHA of `GIT_COMMIT`.

### 4.3 Exception Handling for AMF, SMF, UDM

For the following Network Functions:

* AMF
* SMF
* UDM

The `common-src` commit can be overridden using Jenkins parameters:

* `amf_common_src_commit`
* `smf_common_src_commit`
* `udm_common_src_commit`

If override parameters are provided:

* The specified commit is used instead of the default.

If override parameters are not provided:

* They behave exactly like NRF, AUSF, UPF, and UDR.
* They use the current `common-src` commit.
* No fallback or failure occurs.

## 5. Docker Build Behavior

### 5.1 Build Skipping via Labels (MR Only)

If a Merge Request contains the label:

```
Documentation
```

and does **not** contain:

* `CI`
* `RETRIGGER-CI`

Then:

* Docker builds are skipped.
* The full CI suite does not run.

This allows documentation-only changes to bypass builds.

### 5.2 Parallel Batch Execution

* Docker builds for Network Functions run in parallel batches.
* All Docker images are built with `--no-cache` option, regardless of whether the build is triggered
  by a Merge Request or a Push event.
* Currently, Docker images are built only for the AMD64 architecture.
* If a Network Function fails in Batch 1:

  * Subsequent batches do not run.
  * The pipeline stops early.
This is to ensure early failure detection and efficient resource usage without overloading it.
