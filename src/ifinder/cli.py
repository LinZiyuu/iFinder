from __future__ import annotations

import argparse
import asyncio
import logging

from ifinder import config, pipeline


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ifinder", description="iFinder iTrue discovery pipeline (PFCP + GTP-C)")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run DA→VA→EA across a scope")
    run.add_argument("--scope", required=True, help="path to a scope file (under scope/pfcp/ or scope/gtpc/)")
    run.add_argument("--patterns", required=True, help="comma-separated pattern ids, e.g. PA1,PA2")
    run.add_argument("--target", default=None, help="run only this target name from the scope")
    run.add_argument(
        "--stage",
        choices=list(pipeline.STAGES),
        default=None,
        help="run only this stage (vetting/exploitation load the upstream artifact from disk); "
        "default = full DA→VA→EA",
    )
    run.add_argument("--no-exploit", action="store_true", help="full run but skip EA (ignored if --stage given)")
    run.add_argument(
        "--compose-file",
        default=None,
        help="explicit docker-compose path for the EA testbed (overrides auto-discovery). The EA "
        "auto-derives per-NF routing (per-protocol NF host + container) by parsing this file.",
    )
    run.add_argument(
        "--env-file",
        default=None,
        help="env-file passed to docker compose (e.g. open5gs .env); omit for free5gc",
    )
    run.add_argument(
        "--no-manage-testbed",
        action="store_true",
        help="reuse an already-running testbed: skip 'up -d'/'down -v' (still restarts the NF between attempts)",
    )
    run.add_argument(
        "--candidate",
        default=None,
        help="EA only: comma-separated candidate ids to exploit (e.g. DA-PA1-006); default = all FEASIBLE",
    )
    run.add_argument("--model", default=config.DEFAULT_MODEL, help="Claude model id")
    run.add_argument("-v", "--verbose", action="store_true", help="show each tool call live (DEBUG)")
    run.set_defaults(func=_cmd_run)
    return p


def _cmd_run(args: argparse.Namespace) -> None:
    pattern_ids = [p.strip() for p in args.patterns.split(",") if p.strip()]
    candidate_ids = [c.strip() for c in args.candidate.split(",") if c.strip()] if args.candidate else None
    asyncio.run(
        pipeline.run_scope(
            scope_file=args.scope,
            pattern_ids=pattern_ids,
            run_exploitation=not args.no_exploit,
            target=args.target,
            stage=args.stage,
            model=args.model,
            compose_file=args.compose_file,
            env_file=args.env_file,
            manage_testbed=not args.no_manage_testbed,
            candidate_ids=candidate_ids,
        )
    )


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    if getattr(args, "verbose", False):
        # ifinder.* to DEBUG (shows every Grep/Glob/Read) without third-party log noise
        logging.getLogger("ifinder").setLevel(logging.DEBUG)
    args.func(args)


if __name__ == "__main__":
    main()
