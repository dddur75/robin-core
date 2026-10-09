"""Trace les tests et, sur demande, le jumeau ; aucune donnée réseau externe."""

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import threading
from pathlib import Path
from zoneinfo import TZPATH

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve()


def install_hook():
    log = os.open(os.environ["ROBIN_TRACE_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    state = threading.local()

    def hook(event, args):
        if getattr(state, "busy", False):
            return
        state.busy = True
        try:
            record = None
            if event == "open" and isinstance(args[0], (str, bytes)):
                path = Path(os.fsdecode(args[0])).absolute()
                record = ["open", str(path.resolve()), str(args[1]), args[2]]
            elif event == "subprocess.Popen":
                executable, argv, cwd, env = args
                executable = os.fsdecode(executable)
                resolved = shutil.which(executable) or executable
                record = ["subprocess.Popen", str(Path(resolved).resolve())]
                if not Path(resolved).is_file():
                    record[0] = "subprocess.attempt"
                if Path(resolved).resolve() == Path(sys.executable).resolve():
                    prefix = (f"import os,runpy; os.environ['ROBIN_TRACE_LOG']={os.environ['ROBIN_TRACE_LOG']!r};"
                              f"runpy.run_path({str(SCRIPT)!r}, run_name='__audit_hook__');")
                    if "-c" in argv:
                        index = argv.index("-c") + 1
                        argv[index] = prefix + f"exec(compile({argv[index]!r}, '<string>', 'exec'))"
                    else:
                        index = next(i for i, arg in enumerate(argv[1:], 1) if not arg.startswith("-"))
                        target, tail = argv[index], argv[index + 1:]
                        module = index > 1 and argv[index - 1] == "-m"
                        start = index - 1 if module else index
                        method = "run_module" if module else "run_path"
                        argv[start:] = ["-c", prefix + f"import sys; sys.argv={[target, *tail]!r};"
                                        + f"runpy.{method}({target!r}, run_name='__main__')"]
                elif record[0] != "subprocess.attempt" and Path(resolved).name not in {"git", "gh", "git.exe", "gh.exe"}:
                    record[0] = "subprocess.denied"
                    os.write(log, (json.dumps(record) + "\n").encode())
                    raise OSError("TRACE_PROGRAMME_EXTERNE_INTERDIT")
            elif event == "socket.connect":
                address = args[1]
                if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
                    raise RuntimeError("TRACE_RESEAU_EXTERNE_INTERDIT")
            if record:
                os.write(log, (json.dumps(record) + "\n").encode())
        finally:
            state.busy = False

    sys.addaudithook(hook)


def main():
    with tempfile.TemporaryDirectory(prefix="robin-trace-", dir=ROOT.parent) as temporary:
        workspace = Path(temporary).resolve()
        log = workspace / "audit.jsonl"
        log.touch()
        os.environ["ROBIN_TRACE_LOG"] = str(log)
        os.environ["TMPDIR"] = str(workspace)
        tempfile.tempdir = str(workspace)
        os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        for key in list(os.environ):
            if key.startswith("R2_") or key in {"THE_ODDS_API_KEY", "ODDS_API_KEY",
                                                "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"}:
                os.environ.pop(key)
        os.chdir(ROOT)
        sys.path[:0] = [str(ROOT), str(ROOT / "src")]
        os.environ["PYTHONPATH"] = os.pathsep.join(sys.path)
        if sys.argv[1:2] == ["--jumeau"]:
            command = [sys.executable, str(ROOT / "scripts/jumeau.py"), *sys.argv[2:]]
        else:
            command = [sys.executable, "-m", "pytest", "-q",
                       f"--basetemp={workspace / 'pytest'}", *sys.argv[1:]]
        # Le worker et chaque enfant Python installent le même hook, y compris -I.
        install_hook()
        result = subprocess.run(command, check=False).returncode
        events = [json.loads(line) for line in log.read_text().splitlines()]
        python_roots = {Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve()}
        python_roots.update(Path(p).resolve() for p in sysconfig.get_paths().values())
        python_roots.update(Path(p).resolve() for p in TZPATH)
        runtime = {Path(os.devnull), *(Path(p).resolve() for p in (shutil.which("git"), shutil.which("gh")) if p)}
        shared = {Path(e[1]) for e in events if e[0] == "open" and e[3] & os.O_CREAT
                  and Path(e[1]).parent == Path("/dev/shm")}
        reads, programs, external, attempts = set(), set(), set(), set()
        for event in events:
            path = Path(event[1])
            if event[0] == "subprocess.Popen":
                programs.add(path)
            elif event[0] == "subprocess.denied":
                external.add(path)
            elif event[0] == "subprocess.attempt":
                attempts.add(path)
            elif not event[3] & os.O_WRONLY:
                reads.add(path)
                if not (path.is_relative_to(ROOT) or path.is_relative_to(workspace)
                        or any(path.is_relative_to(p) for p in python_roots)
                        or path in runtime or path in shared or (path.name == "mountinfo" and path.parent.parent == Path("/proc")
                                               and path.parent.name.isdecimal())):
                    external.add(path)

        def label(path):
            if path.is_relative_to(ROOT):
                return str(path.relative_to(ROOT))
            if path.is_relative_to(workspace):
                return "$TRACE/" + str(path.relative_to(workspace))
            return str(path)

        lines = ["# Dépendances observées", "", f"Commande : `{command[2:]}`.",
                 f"Code de sortie : {result}. Entrées externes non autorisées : {len(external)}.",
                 "", "Les temporaires générés, Python et ses paquets, `/dev/null` et",
                 "`/proc/*/mountinfo` (identité du stockage) et les zones horaires Python sont des données d’exécution.",
                 "Le contrôle couvre les tests exercés ; le jumeau nécessite `--jumeau` en phase 2.",
                 "", "## Chemins ouverts en lecture", ""]
        lines.extend(f"- `{label(p)}`" for p in sorted(reads))
        lines.extend(["", "## Programmes lancés", ""])
        lines.extend(f"- `{p}`" for p in sorted(programs))
        lines.extend(["", "## Programmes inexistants (tentatives, aucun lancement)", ""])
        lines.extend(f"- `{label(p)}`" for p in sorted(attempts))
        lines.extend(["", "## Entrées externes non autorisées", ""])
        lines.extend(f"- `{p}`" for p in sorted(external))
        (ROOT / "DEPENDANCES.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        print(f"TRACE : {len(reads)} chemins lus, {len(programs)} programmes, "
              f"{len(external)} entrées externes non autorisées ; tests={result}")
        return result or bool(external)


if __name__ == "__audit_hook__":
    install_hook()
elif __name__ == "__main__":
    raise SystemExit(main())
