<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<table style="border-collapse: collapse; border: none;">
  <tr style="border-collapse: collapse; border: none;">
    <td style="border-collapse: collapse; border: none;">
      <a href="http://www.openairinterface.org/">
         <img src="./images/oai_final_logo.png" alt="" border=3 height=50 width=150>
         </img>
      </a>
    </td>
    <td style="border-collapse: collapse; border: none; vertical-align: center;">
      <b><font size = "5">OpenAirInterface NRF Feature Set</font></b>
    </td>
  </tr>
</table>

**Table of Contents**

1. [5GC Service Based Architecture](#1-5gc-service-based-architecture)
2. [OAI NRF Available Interfaces](#2-oai-nrf-available-interfaces)
3. [OAI NRF Feature List](#3-oai-nrf-feature-list)

# 1. 5GC Service Based Architecture #

![5GC SBA](./images/5gc_sba.png)

# 2. OAI NRF Available Interfaces #

| **ID** | **Interface** | **Status**         | **Comment**                                                               |
| ------ | ------------- | ------------------ | -------------------------------------|
| 1      | Nnrf          | :heavy_check_mark: | Between NRF and other NFs            |
                                                             

# 3. OAI NRF Feature List #

Based on document **3GPP TS 23.501 v16.14.0 (Section 6.2.6)**.

| **ID** | **Classification**                                                              | **Status**         |   **Comments**                     |
| ------ | ------------------------------------------------------------------------------- | ------------------ | ---------------------------------- |
| 1      | Supports service discovery function                                             | :heavy_check_mark: |                                    |
| 2      | Supports P-CSCF discovery                                                       | :x:                |                                    |
| 3      | Maintains the NF profile of available NF instances and their supported services | :heavy_check_mark: |                                    |
| 4      | Maintains SCP profile of available SCP instances                                | :x:                |                                    |
| 5      | Supports SCP discovery by SCP instances                                         | :x:                |                                    |
| 6      | Notifies about newly registered/updated/ deregistered NF and SCP instances      | :x:                |                                    |
| 7      | Maintains the health status of NFs and SCP                                      | :heavy_check_mark: | Partially, only for status of NFs  |
| 8      | Notifies about newly registered/updated/ deregistered NF and SCP instances      | :x:                |                                    |

In the context of Network Slicing, based on network implementation, multiple NRFs can be deployed at different levels:

| 9      | PLMN level (the NRF is configured with information for the whole PLMN)          | :x:                |                                    |
| 10     | Shared-slice level                                                              | :x:                |                                    |
| 11     | Slice-specific level                                                            | :x:                |                                    |

In the context of roaming, multiple NRFs may be deployed in the different networks:

| 11     | the NRF(s) in the Visited PLMN configured with information for the visited PLMN | :x:                |                                    |
| 11     | the NRF(s) in the Home PLMN configured with information for the home PLMN       | :x:                |                                    |

