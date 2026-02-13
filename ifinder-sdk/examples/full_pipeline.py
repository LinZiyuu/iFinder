from ifinder_sdk import IFinderClient


def main() -> None:
    client = IFinderClient()
    artifact = client.run_pipeline(
        pattern="PA1.json",
        target_codebase="/path/to/open5gs",
        scan_dirs=["src"],
        output_root="outputs",
        target_version="v2.7.6",
        persist_artifacts=True,
    )
    print("pipeline done")
    print(f"discovery: {len(artifact['discovery'].candidates)} candidates")
    print(f"vetting feasible: {artifact['vetting'].statistics.feasible}")
    print(f"exploitation results: {len(artifact['exploitation'])}")


if __name__ == "__main__":
    main()
