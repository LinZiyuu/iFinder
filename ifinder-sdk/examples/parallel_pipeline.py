"""Multi-pattern pipeline example for iFinder SDK."""

from ifinder_sdk import IFinderClient


def main() -> None:
    client = IFinderClient()
    patterns = ["PA1.json", "PA2.json", "PB1.json"]

    artifacts = []
    for pattern in patterns:
        artifact = client.run_pipeline(
            pattern=pattern,
            target_codebase="/path/to/open5gs",
            scan_dirs=["src"],
            output_root=f"outputs/{pattern.replace('.json', '')}",
            target_version="v2.7.6",
            persist_artifacts=True,
        )
        artifacts.append(artifact)

    total = sum(len(item["discovery"].candidates) for item in artifacts)
    print(f"finished {len(patterns)} pattern runs, total candidates={total}")


if __name__ == "__main__":
    main()
