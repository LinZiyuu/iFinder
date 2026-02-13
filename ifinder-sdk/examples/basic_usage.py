from ifinder_sdk import IFinderClient, IFinderPaths


def main() -> None:
    client = IFinderClient(
        paths=IFinderPaths(
            pattern_dir="pattern",
            procedure_dir="protocol/pfcp/procedure",
            message_schema_path="protocol/pfcp/generated/message_schemas.normalized.json",
        )
    )

    discovery = client.phase1_discover(
        pattern="PA1.json",
        target_codebase="/path/to/open5gs",
        scan_dirs=["src"],
        target_version="v2.7.6",
    )
    print(f"discovered candidates: {len(discovery.candidates)}")


if __name__ == "__main__":
    main()
