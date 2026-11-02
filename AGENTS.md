Keep code changes minimal and functional.
Keep comments and their usage as minimal as possible.
Keep to the functionality described in the paper.
The codebase is to be cleaned up for release of the code, functionality should not change and stay aligned with the paper.

In your output, stay concise and practical.

## Project
Active warden: pulls packets off Netfilter `FORWARD`/`mangle`, edits in-flow with Scapy, verdicts accept/drop/re-queue. See [ARCHITECTURE.md](ARCHITECTURE.md).

Layout: `web_warden.py` (entry) → `cli.py` (argparse, startup, shutdown; owns the target/process lists) → `target.py` (`Target`: per-target state, process/queue lifecycle), `iptables.py` (NFQUEUE rules, used queue numbers), `pipeline.py` (per-packet decision + per-queue `QueueState`), `flow.py` (occurrence tracking), `packet.py` (operations on one packet), `config_validation.py`. Per-queue/per-packet state is passed as arguments; `args` and `infected` are parameters, not globals.

## Environment
- Managed by `uv`; Python pinned to 3.13 (`netfilterqueue` has no 3.14 wheels). `uv sync` to install.
- Syntax/type check: `uv run pyright` — 14 errors, 1 warning, all expected noise, no bugs: `"IP"/"TCP" not defined`, because pyright does not expand `from scapy.all import *` (fine at runtime); the same star import causes the scapy `Packet` vs local `class Packet` assignment error and the wildcard-import warning; and `Packet.replace` has three union-type complaints because `getReplaceChar` returns `int | str | bytes`.
- Runs on Linux as root only (creates iptables NFQUEUE rules); needs `libnetfilter_queue` headers.

## Running
- Entry `web_warden.py`; `-tl <target-list>` (default `targets.ini`), one of `-srcm/-dstm/-ethm` (default `-ethm`), one of `-seqp/-parp` (default `-parp`), `--nat` (conntrack pre-NAT match; default off = non-NAT forwarding), `-ql/--queue-len <packets>` (kernel NFQUEUE depth, default 1024), `-ct/--cleaner-timeout <seconds>` (idle time before the state cleaner evicts a tracked flow, default 60). Long options use dashes throughout.
- Two configs: `targets.ini` (target list) + `malware.yaml` (operations); `-tl`/`-mc` take paths, only the defaults are cwd-relative.
- Infected-host IP is set in `targets.ini` (`[warden]` section, `infected_ip`); required at startup.
