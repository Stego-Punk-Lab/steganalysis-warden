# Active Warden to Analyze and Counter Stegomalware

This repository contains an active warden that can be used to analyze and counter stegomalware in research laboratories. The warden is a GNU/Linux command-line tool that sits on an intermediate node between an infected host and its command-and-control (C2) server. It pulls packets off the Netfilter `FORWARD`/`mangle` hook, edits them in-flow with [Scapy](https://scapy.readthedocs.io/), and returns an accept / drop / re-queue verdict. This enables disrupting the malicious connection without outright dropping it.

| [Friedrich Gross](https://orcid.org/0009-0004-4772-0459), [Denis Petrov](https://orcid.org/0009-0000-7131-6844), [Pascal Ruffing](https://orcid.org/0009-0001-3540-983X), [Sebastian Zillien](https://scholar.google.de/citations?user=kdCKry4AAAAJ&hl=de), [Steffen Wendzel](https://scholar.google.de/citations?user=DZqkZ1IAAAAJ&hl=de&oi=ao): *A Warden to Analyze and Counter Stegomalware Activities*, in Proc. *Availability, Reliability and Security. ARES 2026 International Workshops* (CUING 2026), LNCS 16902, pp. 165–182, Springer, 2026. [official paper](https://doi.org/10.1007/978-3-032-35586-7_10) |
|----|

Notes:
- Documentation can be found in this repository: [ARCHITECTURE.md](ARCHITECTURE.md) maps the paper (Sect. 3) onto the code, [OPS_AND_TYPES.md](OPS_AND_TYPES.md) documents the config files, operations and packet-field types, and [CHANGES_SINCE_PAPER.md](CHANGES_SINCE_PAPER.md) records where the released code diverges from the paper (e.g. the non-NAT deployment mode).
- The warden was developed and evaluated on a testbed as described by Zillien et al., *A Development Framework for TCP/IP Network Steganography Malware Detection* ([DOI](https://doi.org/10.1145/3658664.3659651)).
- The warden runs on **GNU/Linux as root only**, as it creates Netfilter rules (via the iptables frontend).

The warden is intended for the disruption of C2 channels of web-tunneling stegomalware (e.g. tools that tunnel over HTTP, TLS or DNS). It can edit any supported protocol and header field (IP, TCP, UDP, ICMP, HTTP, DNS, TLS) and is also able to introduce adverse network conditions such as artificial latency or packet loss. Cross-packet occurrence tracking lets it target a specific packet in a sequence.

## Why the Warden is Useful

Most network-level defenses against covert channels focus on *traffic normalization*, which reshapes all traffic to strip embedded messages. Actively *counterattacking* a malicious connection, so as to cause reconnects, slow down instruction execution, or push the malware into fail-states, is far less explored. This process requires an understanding of the target that is hard to obtain when the C2 is encrypted or unavailable.

The warden provides the scientific community with a tool to **arbitrarily edit packets in real time, in-flow**, as part of black-box or gray-box testing of malware and its C2 infrastructure. Because the edits happen on individual packets on the wire, the effect of a given manipulation can be gauged directly from network recordings, C2 output, or client behavior. In the paper we show that even simple manipulations can reliably disrupt popular remote access tools (Sliver, AsyncRAT) and a DNS tunnel (Iodine) without fully severing the connection. Examples include dropping every *n*th packet, adding a few milliseconds of latency, replacing a single HTTP status code, or substituting a TCP RST.

## How to use the Warden?

### 1. Install

The warden requires a **GNU/Linux** operating system, the `libnetfilter_queue` headers, and must run as **root**. The Python versions used by the authors for development and testing were 3.13 and 3.14 (GIL enabled). Dependencies are managed by [`uv`](https://docs.astral.sh/uv/):

```
$ uv sync
```

### 2. Describe the target(s): `targets.ini`

The target list names the infected host and one section per C2 target. Each target lists one or more C2 IP addresses (several addresses model a distributed C2) and the malware whose operations should be applied to it:

```
[warden]
infected_ip = 192.168.7.7

[sliver-c2]
ips: ['210.210.210.210']
malware: sliver
```

The `[warden] infected_ip` is required: it is the IP of the infected host the warden sits in front of.

### 3. Describe the operations: `malware.yaml`

For each malware name, the operation config lists the operations to perform, the protocol fields each one targets, and its settings. For example, to drop every 5th packet associated with Sliver:

```
sliver:
  operations:
    drop-1:
      settings:
        enabled: True
        on_every: 5
      protocols:
        IP:
          - ttl
```

**What do the keys mean?** `drop-1` is the operation; the `-1` suffix only makes the key unique and is stripped for dispatch. `protocols` maps each protocol to the list of fields to target (here IP `ttl`, used as the per-packet trigger). `settings` holds the operation's arguments: `enabled: True` activates it (default is `True` when omitted), and `on_every: 5` applies it on every 5th occurrence of the field in a flow. The available operations (drop, reset, latency, replace, set, injection, the two search operations, none, zero, …) and the shared settings (`on_every`, `on_every_cross_flow`, `chance`, `skip_rest`, `trigger_pattern`) are documented in [OPS_AND_TYPES.md](OPS_AND_TYPES.md).

### 4. Run the warden

The warden is run through `uv` as root:

```
$ sudo uv run web_warden.py -tl targets.ini -mc malware.yaml -ethm -parp
```

**What do the parameters mean?** `-tl` and `-mc` point to the two config files above. `-ethm` (either-address, the default) manipulates packets whose source *or* destination is defined in a target; use `-srcm` / `-dstm` to restrict to the C2→infected or infected→C2 direction. `-parp` (parallel, the default) processes each arriving packet in a thread pool; `-seqp` processes one packet at a time. Add `--nat` when the warden runs on a node performing NAT (as was the case in the paper). Without it, the warden defaults to matching the on-the-wire addresses.

Full option reference:

| Option | Default | Meaning |
|---|---|---|
| `-tl`, `--target-list` | `targets.ini` | path to the target list |
| `-mc`, `--malware-config` | `malware.yaml` | path to the operation config |
| `-srcm` / `-dstm` / `-ethm` | `-ethm` | edit packets with a malicious source / destination / either address |
| `-seqp` / `-parp` | `-parp` | process packets one at a time / in a thread pool |
| `--nat` | off | match the pre-NAT destination via conntrack (warden on a NAT router) |
| `-ql`, `--queue-len` | 1024 | kernel NFQUEUE depth before further packets are dropped |
| `-ct`, `--cleaner-timeout` | 60 | idle seconds before a tracked flow is evicted |
| `-ll`, `--log-level` | warning | log level |

`-srcm/-dstm/-ethm` and `-seqp/-parp` are mutually exclusive pairs.

### 5. Shut down

The warden runs until it receives a `KeyboardInterrupt` (Ctrl-C) or `SIGTERM`. On shutdown it tears down every Netfilter rule it created and exits its processes. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full per-packet decision pipeline (Fig. 1, steps 1–10).

## Citation

```bibtex
@inproceedings{Gross_2026_Warden,
  title     = {A Warden to Analyze and Counter Stegomalware Activities},
  author    = {Gross, Friedrich and Petrov, Denis and Ruffing, Pascal and Zillien, Sebastian and Wendzel, Steffen},
  booktitle = {Availability, Reliability and Security. ARES 2026 International Workshops},
  series    = {Lecture Notes in Computer Science},
  pages     = {165--182},
  year      = {2026},
  publisher = {Springer Nature Switzerland},
  doi       = {10.1007/978-3-032-35586-7_10}
}
```

## Acknowledgement 
This work has been supported by the Agentur für Innovation in der Cybersicherheit GmbH. The Agentur für Innovation in der Cybersicherheit GmbH did not interfere in the research process and its results. https://www.cyberagentur.de/programme/hsk/ see in https://attribut.cs.uni-magdeburg.de/. 
