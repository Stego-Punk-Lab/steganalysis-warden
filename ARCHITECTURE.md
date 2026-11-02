# Warden Architecture (paper ↔ code)

Correlates *"A Warden to Analyze and Counter Stegomalware Activities"* (Sect. 3) with
this codebase. Where the released code diverges from or extends the paper is recorded in
[CHANGES_SINCE_PAPER.md](CHANGES_SINCE_PAPER.md). Usage information, namely the operation
arguments and the packet field types, is documented in [OPS_AND_TYPES.md](OPS_AND_TYPES.md).

The warden is a GNU/Linux Python CLI on a router between an infected host and a C2 server. It
pulls packets off the `FORWARD` chain of the Netfilter `mangle` table, edits them in-flow with
Scapy, and issues an accept / drop / re-queue verdict.

## Code layout
| Module | Contents |
|---|---|
| `web_warden.py` | entry point: calls `cli.main()` |
| `cli.py` | argparse, startup checks, config loading, process startup and shutdown |
| `target.py` | `Target`: per-target state and process/queue lifecycle |
| `iptables.py` | NFQUEUE rule build/teardown |
| `flow.py` | field/value gate, chance rolls, occurrence tracking |
| `pipeline.py` | per-packet decision (`process_packet`, `finalize`) and the per-queue `QueueState` |
| `packet.py` | `Packet`: the individual operations and field access, plus the `OPERATIONS` dispatch registry |
| `config_validation.py` | `malware.yaml` validation |

## Deployment / NAT (Fig. 2)
The warden runs between the Infected Host `192.168.7.7` and the Fake Uplink Server on the Router (our testbed is described in [this paper](https://doi.org/10.1145/3658664.3659651)).
`make_targets()` (`cli.py`) reads the infected-host IP from `targets.ini` (`[warden]` section, `infected_ip`) into
`infected`. Queue rule matching (`iptables.py`) and the default non-NAT vs. `--nat` deployment
modes: [CHANGES_SINCE_PAPER.md](CHANGES_SINCE_PAPER.md).

## Config inputs (Phase 1 – Configuration Parsing)
| Paper | File | Code |
|---|---|---|
| Target list | `targets.ini` | `make_targets()` via configparser (cli.py) |
| Operation config | `malware.yaml` | `yaml.safe_load` (cli.py) |
| CLI arguments | n/a | argparse (cli.py) |

The structure of both config files is documented in [OPS_AND_TYPES.md](OPS_AND_TYPES.md#config-files).

## Execution pipeline (Fig. 1, steps 1–10)
| # | Phase / step | Code, File |
|---|---|---|
| 1 | Parse target list + operations + CLI | cli.py |
| 2 | `Target` object per target-list entry | `Target.__init__` target.py, created by `make_targets()`, cli.py |
| 3 | Import operations for target's malware | `associate_modes()` → `target.manipModes`, cli.py |
| 4 | Netfilter rule per target IP | `make_iptables_ips()` `-t mangle -I FORWARD … -j NFQUEUE`, iptables.py |
| 5 | Process per Target object | `make_process()` → `target_callback`, target.py |
| 6 | Process per Netfilter rule/queue | `target_callback()`, target.py |
| 7 | Rule process binds its queue (FIFO / 200-thread pool) | `queue_process_callback()`, target.py |
| 8 | Apply operations to packets | `process_packet()`, pipeline.py |
| 9 | Receive KeyboardInterrupt | main loop, cli.py |
| 10 | Teardown rules, exit processes | `teardown_all()`, cli.py |

Callback per concurrency mode: `seqp_callback` (FIFO) / `parp_callback` (pool.submit) target.py.

## Per-packet decision (Sect. 3.2, step 8)
`pipeline.process_packet`, on a Scapy packet wrapped by `Packet.__init__`. For each
op × protocol × field the checks run in the paper's order; **apply beats skip** on conflict
(pipeline.py):

1. Field presence: `flow.has_field_and_value()` requires the field to hold a value other than `None`
2. Occurrence tracking (every *n*th occurrence): `flow.flow_occurrence_check()`
3. Skipping by chance: `flow.roll_check()`
4. Trigger pattern on the raw packet bytes: `Packet.bytes_pattern`, called from `process_packet`
   for operations that set `trigger_pattern`; if the pattern does not match, the operation is skipped

A field Scapy left unset (`None`, e.g. `TLS.pad`/`TLS.padlen` on a record the warden cannot
decrypt) counts as absent; an empty value such as `TLS.iv` (`b''`) passes the gate and `replace`
then does nothing.

Dispatch: `OPERATIONS[packet.operation_base(mode)]`. Verdicts: `drop`→`pkt.drop()`,
`repeat`→`pkt.repeat()` (re-queue), otherwise `finalize()` + `pkt.accept()`. `finalize()` rewrites
lengths/checksums only when an operation changed the packet (`Packet.modified`); otherwise the
original payload is forwarded untouched. `skip_rest` short-circuits the remaining operations
(`flow.skip_rest`). Any failure on this path, including a value that cannot be serialized after
an edit, results in the packet being accepted **unmodified**; partial edits are not forwarded in
this case.

## Cross-packet flow tracking (abstract; Sect. 3.2)
Per-queue `states` dict keyed by flow-id (sorted port pair, `flow.make_flow_id`), holding the
`on_every` and `on_every_cross_flow` counters. A background `state_cleanup` thread (`target.py`)
evicts flows idle longer than `-ct`/`--cleaner-timeout` (60 s by default); it is a daemon waiting
on a stop event, so the queue process always exits.

## Protocol coverage
`HTTP` fields dissect on ports 80/8080 only (scapy's `bind_bottom_up`); on any other port an
`HTTP`-targeted operation does nothing. The warden is IPv4-only, and link-layer `Ether`/`ARP` are
unreachable at the layer-3 `mangle`/`FORWARD` hook.

## Accepted loss

The kernel silently drops packets once an NFQUEUE is full (`-ql`, default 1024); overflow requires
deliberate overload and no fail-open mechanism is used. Un-verdicted packets are lost at shutdown.
