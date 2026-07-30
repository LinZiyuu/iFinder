<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# RELEASE NOTES:

## v2.2.1 -- March 2026

* Change of license from OAI Public License v1.1 to CSSL v1.0
* Re-license documentation to the CC-BY-4.0 License
* Re-license orchestration files (docker compose yaml files, health scripts, openshift build files)
  and CI-scripts under the MIT License

## v2.2.0 -- December 2025

* Fixes
  - Update LTTNG to v0.15.0 to avoid building issues
* Tech Debt
  - Add support for Ubuntu 24.04
  - Add support for RHEL 10, update container images to UBI 10
  - Fix build issue in non-containerized environment

## v2.1.0 -- August 2024

* Features
  - Update UDM APP structure
  - Use HTTP Request Timeout parameter from Conf file
* Fixes
  - Fix HTTP/2 server shutdown
* Tech Debt
  - Code cleanup
  - Stopping support for RHEL8/Rocky8 in favor of RHEL9/Rocky9
  - Removing unneccessary packages from target images
  - Cleanup UDM client and add connection handling mechanism
  - Move UDM SBI models to common src git submodule
  - HTTP client cpr library refactoring effort

## v2.0.1 -- January 2024

* Fixes
  - Remove NRF dependency from SMF

## v2.0.0 -- December 2023

* Features
  - Support YAML configuration file
    * Yaml validation default value
* Fixes
  - Fixed HTTP/2 issue for SDM sm-data API
* Tech debt
  - Updated common models to 3GPP TS 29.571 Release 16.13.0 and moved them to the shared common submodule
  - Switching to clang-format-12
  - Published image on Docker-Hub is using now Ubuntu-22 as base image
    * Ubuntu-18 is no longer supported

## v1.5.1 -- May 2023

* HTTP2 Fix: Removed duplicate request handler
* Code Refactoring for:
  * Logging mechanism (runtime log level selection)
  * Installation / build scripts
  * Continuous Integration scripts
* Published image on Docker-Hub is using now Ubuntu-20 as base image
  * We will soon obsolete the build system for Ubuntu18.04

## v1.5.0 -- January 2023

* feat(fqdn): giving some time for FQDN resolution
* Docker image improvements
* Fixed docker exit by catching SIGTERM
* release mode does not use libasan anymore --> allocation of 20T virtual memory is no longer done
* Ubuntu22 and cgroup2 support

## v1.4.0 -- July 2022

* Fix HTTP/2 support
* NRF Registration and heartbeat exchange
* Official images produced by CI are pushed to `oaisoftwarealliance` Docker-Hub Team account
* Reduce image size

## v1.3.0 -- January 2022

* Experimental support for Event Exposure
* Added HTTP2 support
* Fix static addr allocation
* Fix build issue
* Docker build optimizations

## v1.2.1 -- October 2021

* Fix build issue

## v1.2.0 -- September 2021

* Initial public release
* NRF registration
  - with FQDN DNS resolution
* Full support for Ubuntu18 and RHEL8

## v1.0.0 -- June 2021

* Initial private release

