<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# RELEASE NOTES:

## v2.2.1 -- March 2026

* Change of license from OAI Public License v1.1 to CSSL v1.0
* Re-license documentation to the CC-BY-4.0 License
* Re-license orchestration files (docker compose yaml files, health scripts, openshift build files)
  and CI-scripts under the MIT License

## v2.2.0 -- December 2025

* Features
  - PCF Provisioning API: Introduced support for provisioning Policy Decisions,
  PCC Rules, QoS Data, and Traffic Control Data.
* Fixes
  - HTTP/2 PUT request for each endpoint
  - LTTNG build issue
* Future Fixes
  - Add support for Ubuntu 24.04
  - Add support for RHEL 10, update container images to UBI 10
  - Fix build issue in non-containerized environment

## v2.1.0 -- August 2024

* Features
  - Add possibility to read QoS values from file
* Fixes
  - Fix HTTP/2 server shutdown
  - Use new FlowDirection fix
* Tech Debt
  - Stopping support for RHEL8/Rocky8 in favor of RHEL9/Rocky9
  - HTTP client cpr library refactoring effort
  - Resynch PCF with common source git-submodule and use utils from there

## v2.0.0 -- December 2023

* Features
  - Support YAML configuration file
    * Yaml validation default value
  - Add support for traffic steering rules
  - Add support for redirection rules
* Fixes
  - Handling boolean values in yaml parsing for policies
* Tech debt
  - Updated common models to 3GPP TS 29.571 Release 16.13.0 and moved them to the shared common submodule
  - Updated PCF models to Release 16.17.0 and moved them to the shared common submodule
  - Switching to clang-format-12
  - Published image on Docker-Hub is using now Ubuntu-22 as base image
    * Ubuntu-18 is no longer supported

## v1.5.1 -- May 2023

* Add HTTP/2 support
* Code Refactoring for:
  * Logging mechanism (runtime log level selection)
  * Installation / build scripts
  * Continuous Integration scripts
* Published image on Docker-Hub is using now Ubuntu-20 as base image
  * We will soon obsolete the build system for Ubuntu18.04

## v1.5.0 -- January 2023

* Initial release
* NRF registration
* Add Npcf_SMPolicyControl API Create, Update, Delete and Get procedures
* Add file based policy provisioning
* Add policy decision feature based on SUPI, DNN, Slice and default policy
* Fixed docker exit by catching SIGTERM
* release mode does not use libasan anymore --> allocation of 20T virtual memory is no longer done

