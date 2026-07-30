# iFinder

**Understanding Implicit Trust Errors in Core Carrier Networks through Multi-Agent Flaw Discovery and Analysis**

*Accepted at Usenix Security 2026*

## Structure

```
.
├── src/                # iFinder
├── pattern/            # Six implicit-trust flaw patterns 
├── procedure/          # Per-protocol procedure definitions
│   ├── pfcp/           #   PFCP N4 / Sx
│   └── gtpc/           #   GTPv2-C S11 / S5 / S8
├── schema/             # Generated protocol knowledge bases 
│   ├── pfcp/           #   PFCP
│   └── gtpc/           #   GTP-C
├── scope/              
│   ├── pfcp/           #   open5GS, free5GC, OAI 5G, eUPF, SD-Core
│   └── gtpc/           #   OAI EPC, Open5GS LTE
├── target/             # source codebases
│   ├── open5gs_code/
│   ├── free5gc_code/
│   ├── openairinterface_code/
│   ├── eupf_code/
│   └── sdcore_code/
├── testbed/            # Seven Docker Compose testbeds
│   ├── docker-open5gs/     #   open5gs 5G
│   ├── free5gc-compose/    #   free5GC 
│   ├── oai-cn5g-fed/       #   OAI CN5G
│   ├── openair-epc-fed/    #   OAI LTE
│   ├── docker-eupf/        #   eUPF
│   ├── docker-sdcore/      #   SD-Core
│   └── docker-open5gs-lte/ #   open5gs 4G LTE 
├── scripts/            # End-to-end reproduction wrappers (DA → VA → EA), `reproduce_<depth>_<target>`
├── dataset/            # 22 PFCP vulnerabilities curated as ground truth for evaluation
└── README.md           
```

## scripts

- **One-candidate** (`reproduce_one_candidate_<target>.sh`) — first FEASIBLE candidate of pattern PA1; ~10 min each. Targets: open5gs 5G, eUPF, SD-Core, OAI CN5G, free5GC (PFCP/N4), plus OAI EPC and open5gs LTE (GTP-C/S11).
- **Full evaluation** (`reproduce_full_<protocol>_<target>.sh`) — all 6 patterns × every FEASIBLE candidate, with a per-pattern candidates / feasible / confirmed table; 1–4 h, real token cost.

## Responsible Disclosure

We have responsibly disclosed these vulnerabilities to the affected implementation maintainers. The specific CVE IDs are available at https://linziyuu.github.io/iFinder-Website/

# Citation
```bibtex
@article{lin2026understanding,
  title={Understanding Implicit Trust Errors in Core Carrier Networks through Multi-Agent Flaw Discovery and Analysis},
  author={Lin, Ziyu and Wang, Ziting and Li, Xinfeng and Dong, Wei and Wang, XiaoFeng},
  journal={arXiv preprint arXiv:2607.10315},
  year={2026}
}
```