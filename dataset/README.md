# iFinder Ground-Truth Vulnerability Dataset

22 known PFCP vulnerabilities, curated as ground truth.


## Inventory

| id | project | version | nf | interface | CWE | pattern | crash function |
|----|---------|---------|----|-------|-----|---------|----------------|
| [OPEN5GS-PFCP-001](https://github.com/open5gs/open5gs/issues/3840) | open5gs | v2.7.5 | UPF | N4/PFCP | CWE-121 | PA1 | `ogs_ipfw_compile_rule:83` |
| [OPEN5GS-PFCP-002](https://github.com/open5gs/open5gs/issues/2127) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | PA1 | `ogs_pfcp_parse_msg:4009` |
| [OPEN5GS-PFCP-003](https://github.com/open5gs/open5gs/issues/2523) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | PA1 | `ogs_tlv_parse_msg:753` |
| [OPEN5GS-PFCP-005](https://github.com/open5gs/open5gs/issues/3207) | open5gs | v2.4.14 | SMF | N4/PFCP | CWE-617 | PA1 | `ogs_pfcp_parse_user_plane_ip_resource_info` |
| [OPEN5GS-PFCP-006](https://github.com/open5gs/open5gs/issues/3839) | open5gs | v2.7.5 | UPF | N4/PFCP | CWE-121 | PA1 | `ogs_pfcp_extract_node_id:197` |
| [FREE5GC-PFCP-007](https://github.com/free5gc/free5gc/issues/496)  | free5gc | v3.3.0 | UPF | N4/PFCP | CWE-120 | PA1 | `(*IE).UnmarshalBinary:371` |
| [OPEN5GS-PFCP-008](https://github.com/open5gs/open5gs/issues/3841) | open5gs | v2.7.5 | UPF | N4/PFCP | CWE-476 | PA1 | `ogs_ipfw_compile_rule:64` |
| [OPEN5GS-PFCP-009](https://github.com/open5gs/open5gs/issues/3847) | open5gs | v2.7.5 | UPF | N4/PFCP | CWE-125 | PA1 | `ogs_pfcp_node_id_to_string_static:305` |
| [OPEN5GS-PFCP-010](https://github.com/open5gs/open5gs/issues/3207) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | PA1 | `ogs_pfcp_parse_sdf_filter` |
| [OPEN5GS-PFCP-011](https://github.com/open5gs/open5gs/issues/3207) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | PA1 | `ogs_pfcp_parse_volume:500` |
| [FREE5GC-PFCP-012](https://github.com/free5gc/free5gc/issues/746) | free5gc | v3.3.0 | UPF | N4/PFCP | CWE-120 | PA1 | `(*SDFFilterFields).UnmarshalBinary:190` |
| [FREE5GC-PFCP-004](https://github.com/free5gc/free5gc/issues/483) | free5gc | v3.3.0 | UPF | N4/PFCP | CWE-120 | **PA2** | `(*RecoveryTimeStamp).UnmarshalBinary` |
| [OPEN5GS-PFCP-013](https://github.com/open5gs/open5gs/issues/3207) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | **PB1** | `upf_sess_find_by_smf_n4_f_seid:280` |
| [FREE5GC-PFCP-016](https://github.com/free5gc/free5gc/issues/482) | free5gc | v3.3.0 | UPF | N4/PFCP | CWE-120 | **PB1** | `(*IE).UnmarshalBinary:371` |
| [OPEN5GS-PFCP-017](https://github.com/open5gs/open5gs/issues/3727) | open5gs | v2.7.2 | UPF | N4/PFCP | CWE-617 | **PB1** | `upf_sess_set_ue_ip:401` |
| [OPEN5GS-PFCP-018](https://github.com/open5gs/open5gs/issues/3747) | open5gs | v2.7.2 | UPF | N4/PFCP | CWE-617 | **PB1** | `ogs_pfcp_pdr_swap_teid:1365` |
| [OPEN5GS-PFCP-019](https://github.com/open5gs/open5gs/issues/3574) | open5gs | v2.7.2 | UPF | N4/PFCP | CWE-617 | **PB1** | `ogs_pfcp_pdr_swap_teid:1147` |
| [OPEN5GS-PFCP-020](https://github.com/open5gs/open5gs/issues/3642) | open5gs | v2.7.2 | UPF | N4/PFCP  | CWE-787 | **PB1** | `upf_sess_urr_acc_add` |
| [OPEN5GS-PFCP-014](https://github.com/open5gs/open5gs/issues/2128) | open5gs | v2.4.14 | UPF | N4/PFCP | CWE-617 | **PB2** | `ogs_pfcp_xact_find_by_xid:779` |
| [OPEN5GS-PFCP-015](https://github.com/open5gs/open5gs/pull/3040) | open5gs | v2.4.14 | SMF | N4/PFCP| CWE-416 | **PB3** | `smf_sess_remove:1725` |
| [OPEN5GS-PFCP-021](https://github.com/open5gs/open5gs/issues/3964) | open5gs | v2.7.5 | UPF | N4/PFCP | CWE-617 | **PC1** | `upf_sess_add:181` |
| [FREE5GC-PFCP-022](https://github.com/free5gc/free5gc/issues/17) | free5gc | v2.0.2 | UPF | N4/PFCP | CWE-770 | **PC1** | `SelectBufblkOption:80` |

_Total: **22 distinct entries** (17 open5gs + 5 free5gc).
_IDs grouped by pattern class: **001–012 = PA**, **013–020 = PB**, **021–022 = PC**.
_Pattern breakdown: **PA1 × 11** (001, 002, 003, 005, 006, 007, 008, 009, 010, 011, 012), **PA2 × 1** (004), **PB1 × 6** (013, 016, 017, 018, 019, 020), **PB2 × 1** (014), **PB3 × 1** (015), **PC1 × 2** (021, 022).
_Cause class: Syntactic × 12 (PA1 + PA2), Semantic × 8 (PB1 + PB2 + PB3), Resource × 2 (PC1).


