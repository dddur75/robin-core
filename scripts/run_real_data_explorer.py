from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from robin.capture.real_data_explorer import (  # noqa: E402
    AtomicExplorerStore,
    ExplorerRefreshController,
    GhArtifactClient,
    run_refresh_loop,
)
from robin.capture.real_data_questions import run_question_command  # noqa: E402
from robin.capture.real_data_questions_web import make_server  # noqa: E402

QUESTION_OPTIONS = (
    "previous",
    "current",
    "event",
    "sport",
    "market",
    "outcome",
    "point",
    "period",
    "provider",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Serve the private Robin data explorer")
    result.add_argument("--root", type=Path, required=True)
    result.add_argument("--repository", default="dddur75/robin-stades-ng")
    result.add_argument("--workflow-id", default="321915839")
    result.add_argument("--port", type=int, default=4173)
    result.add_argument("--refresh-seconds", type=int, default=300)
    result.add_argument("--refresh-once", action="store_true")
    result.add_argument(
        "--question",
        choices=("acquisitions", "q1", "q3"),
        help="Answer from the verified local store only, without GitHub or a server",
    )
    for name in QUESTION_OPTIONS:
        result.add_argument(f"--{name}")
    result.add_argument("--format", choices=("json", "csv"), default="json")
    result.add_argument("--output", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.question and not all(
        (arguments.root / name).is_dir() for name in ("versions", "staging")
    ):
        # Question mode only reads a complete existing store: the store constructor would
        # otherwise create missing directories.
        sys.stderr.write("LOCAL_STORE_UNAVAILABLE\n")
        return 2
    store = AtomicExplorerStore(arguments.root)
    if arguments.question:
        options = {
            name: getattr(arguments, name)
            for name in QUESTION_OPTIONS
            if getattr(arguments, name) is not None
        }
        code, payload = run_question_command(store, arguments.question, options, arguments.format)
        if code != 0:
            sys.stderr.write(payload.decode("utf-8"))
        elif arguments.output is not None:
            arguments.output.write_bytes(payload)
        else:
            sys.stdout.buffer.write(payload)
        return code
    client = GhArtifactClient(
        repository=arguments.repository,
        workflow_id=arguments.workflow_id,
    )
    controller = ExplorerRefreshController(store, client)
    if arguments.refresh_once:
        changed = controller.refresh_once()
        print("UPDATED" if changed else "UNCHANGED_OR_UNAVAILABLE")
        return 0 if store.current_pointer() is not None else 2

    if store.current_pointer() is None:
        controller.refresh_once()
    server = make_server(store, port=arguments.port)
    stopped = threading.Event()

    refresh_thread = threading.Thread(
        target=run_refresh_loop,
        args=(controller, stopped, arguments.refresh_seconds),
        kwargs={"refresh_immediately": True},
        name="robin-explorer-refresh",
        daemon=True,
    )
    refresh_thread.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        refresh_thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
