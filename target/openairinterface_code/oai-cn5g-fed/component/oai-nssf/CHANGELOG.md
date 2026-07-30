<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# RELEASE NOTES:

## v2.2.1 -- March 2026

* Change of license from OAI Public License v1.1 to CSSL v1.0
* Re-license documentation to the CC-BY-4.0 License
* Re-license orchestration files (docker compose yaml files, health scripts, openshift build files)
  and CI-scripts under the MIT License

## v2.2.0 -- December 2025

* Fixes
  - Update LTTNG to v0.15.0 to avoid build issues
* Future Fixes
  - Add support for Ubuntu 24.04
  - Add support for RHEL 10, update container images to UBI 10
  - Fix build issue in non-containerized environment

## v2.1.0 -- August 2024

* Features
* Fixes
  - Fix HTTP/2 server shutdown
* Tech Debt
  - Stopping support for RHEL8/Rocky8 in favor of RHEL9/Rocky9
  - Move NSSF SBI models to common src git submodule

## v2.0.0 -- December 2023

* Features
  - Support YAML configuration file
    * Yaml validation default value
* Tech debt
  - Updated common models to 3GPP TS 29.571 Release 16.13.0 and moved them to the shared common submodule
  - Switching to clang-format-12
  - Published image on Docker-Hub is using now Ubuntu-22 as base image
    * Ubuntu-18 is no longer supported

## v1.5.1 -- May 2023

* Code Refactoring for:
  * Logging mechanism (runtime log level selection)
  * Installation / build scripts
  * Continuous Integration scripts
* Published image on Docker-Hub is using now Ubuntu-20 as base image
  * We will soon obsolete the build system for Ubuntu18.04

## v1.5.0 -- January 2023

* Docker image improvements
* Fixed docker exit by catching SIGTERM
* release mode does not use libasan anymore --> allocation of 20T virtual memory is no longer done
* Ubuntu22 and cgroup2 support

## v1.4.0 -- July 2022

* Network slice selection for UE registration
* NS-AVAIBALITY API support to CREATE new slice
* Fix bare-metal setup configuration management
* HTTP/2 support for SBI interface
* Official images produced by CI are pushed to `oaisoftwarealliance` Docker-Hub Team account
* Reduce image size

## v1.3.0 -- January 2022

* Initial Public Release
* Docker Optimization

