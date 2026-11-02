# Operations & Field Types

Usage reference: the config file structures, the available operations and their
arguments, and the data types of the packet fields. Collected against Scapy 2.6.1.

## Config files

### `targets.ini` (target list)

```
[warden]
infected_ip = 192.168.7.7

[<target>]
ips = ['200.200.200.200']
malware = sliver
```

- `[warden] infected_ip`: IP address of the infected host (required).
- Every other section names one target.
  - `ips`: a Python list literal of C2 IP addresses (several addresses denote a distributed C2).
  - `malware`: a malware name defined in `malware.yaml`.

### `malware.yaml` (operation config)

```
<malware-name>:
  operations:
    <operation>[-suffix]:
      protocols:
        <Protocol>:
          - <field>
      settings:
        <setting>: <value>
```

- Top level: malware name → `operations`.
- An operation is keyed by its name, optionally suffixed (e.g. `drop-1`); the suffix is
  stripped for dispatch and only makes the key unique.
- `protocols`: protocol → list of fields to target.
- `settings`: the operation's arguments (below). `enabled: false` disables the operation
  at startup; absent means enabled.
- An unknown operation name is rejected at startup.

## Operations

The following shared settings are accepted by every operation:

| Setting | Type | Meaning |
|---|---|---|
| `enabled` | bool | `false`/`no`/`0` disables the operation at startup; absent means enabled |
| `on_every` | int | apply on every *n*th occurrence of a field in a flow (flow id = sorted port pair, or an address sum for IP-level protocols, plus mode/protocol/field) |
| `on_every_cross_flow` | int | as `on_every`, but one counter shared by all flows targeted by the operation via malware name |
| `chance` | int 0–100 | percentage chance to **skip** |
| `skip_rest` | bool | stop processing the target's remaining operations |
| `trigger_pattern` | regex | apply only if the pattern matches the raw packet bytes |

Booleans accept YAML bools and the text forms `true`/`yes`/`on`/`1`.

### drop

Drop the packet.

No specific settings.

### reset

Replace the IP payload with a TCP RST packet: copies SEQ/ACK, sets R/RA (RA when the
trigger packet has ACK), sets `window = 512`, re-queues.

No specific settings.

### latency

Delay the packet.

| Setting | Type | Meaning |
|---|---|---|
| `ms` | int | delay in milliseconds (default 50) |
| `jitter` | int | ± random spread added to `ms` (default 0) |

### replace

Replace one character (or digit) at `index` with `replace_value`.

| Setting | Type | Meaning |
|---|---|---|
| `index` | int | edited character/digit position; defaults to a random one |
| `replace_value` | char | the replacement; a single character (int fields: a digit 0–9) |

Integer fields are clamped to the `prot_dict` low/high bounds. Flag fields
(`IP.flags`, `TCP.flags`) cannot be replaced; `set` must be used instead.

### set

Assign the field's value directly, with no bounds check (never consults `prot_dict`).

| Setting | Type | Meaning |
|---|---|---|
| `value` | any | the value to assign, including flag strings (`RA`) for flag fields |

Required for flag fields (`IP.flags`, `TCP.flags`), which `replace` cannot edit.

### search_packet_bytes

Search-and-replace a regex over the raw packet bytes.

| Setting | Type | Meaning |
|---|---|---|
| `pattern` | regex | what to find; `hex:`-prefixed binary values accepted |
| `replace_value` | text / bytes | the replacement |
| `occurrences` | list | `['all']`, match indices, or the tokens `first`/`last` (`0`/`-1`) |
| `offset` | int | added to each match position (default 0) |
| `literal` | bool | `re.escape` the pattern |

### search_field_string

Search-and-replace a regex over the field, treated as a string.

| Setting | Type | Meaning |
|---|---|---|
| `pattern` | regex | what to find |
| `replace_value` | text | the replacement |
| `occurrences` | list | `['all']`, match indices, or `first`/`last` |
| `offset` | int | added to each match position (default 0) |

### injection

Insert symbols into the field.

| Setting | Type | Meaning |
|---|---|---|
| `index` | int | position of the first inserted symbol; `index == len` appends |
| `amount` | int | number of insertions (default 1); each random symbol goes to `index` + *n*, or to its own random position without `index` |
| `inject_value` | text | symbols to insert as one contiguous sequence; mutually exclusive with `amount` |

### none

Set the field to the pythonic `None`.

No specific settings.

### zero

Set the field to a type-appropriate zero (int `0`, str `'0'`, bytes `b'\x00'`, list `[0]`,
flags `0`).

No specific settings.

### repeat

Re-queue the packet (back of the queue).

No specific settings.

### silent_accept (dev)

Accept without editing or logging.

### print_field_as_string (dev)

Print the targeted field's value.

### print_packet_as_bytes (dev)

Print the raw packet bytes of the packet containing the targeted field.

## Field types

Each field is listed under the Python type returned by Scapy's `getfieldval(field)`. A
`set`/`replace` value must be of this type (or be coercible to it), and the operations'
dispatch matches against it.
Enum fields return the integer, never the text name.

### int

Plain integer and enum fields. `set.value` needs an int; `replace`/`injection` operate on
the decimal text, so `replace_value` for these is a digit 0–9.

- **IP**: version, ihl, tos, len, id, frag, ttl, proto, chksum
- **TCP**: sport, dport, seq, ack, dataofs, reserved, window, chksum, urgptr
- **UDP**: sport, dport, len, chksum
- **ICMP**: type, code, chksum, id, seq, ts_ori, ts_rx, ts_tx, ptr, reserved, length, nexthopmtu
- **DNS**: length, id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qdcount, ancount, nscount, arcount
- **DNSQR**: qtype, unicastresponse, qclass
- **DNSRR**: type, cacheflush, rclass, ttl, rdlen
- **DNSRROPT**: type, rclass, extrcode, version, z, rdlen
- **TLS**: type, version, len, padlen

### bytes

String/raw fields. `set.value` takes bytes or a str (encoded).

- **TCP**: options
- **DNSQR**: qname
- **DNSRR**: rrname
- **DNSRROPT**: rrname
- **TLS**: iv, mac, pad
- **HTTP**: all header fields (`Method`, `Path`, `Host`, `Status_Code`, `Reason_Phrase`, `Content_Length`, …)

### str

IP-address fields (a `str`, scapy `_ScopedIP`).

- **IP**: src, dst (protected; write operations reject these fields)
- **ICMP**: gw, addr_mask (protected; write operations reject these fields)

### FlagValue

Flag bitfields. Must be set as a whole (`set`, with a flag string like `RA` or an int);
they cannot be partially edited.

- **IP**: flags
- **TCP**: flags

### list

Packet-list fields.

- **IP**: options
- **DNS**: qd, an, ns, ar
- **DNSRROPT**: rdata
- **TLS**: msg

### varies

Fields implemented as `MultipleTypeField`; their type depends on the packet content.

- **DNSRR**: rdata (unstable; str, bytes or list depending on the RR type; supporting it would require a per-type extension, which is not implemented)

### float

No listed field uses it.

### Computed / encrypted fields

Read as absent (`None`) until Scapy fills them in; targeting them before that silently does
nothing.

- **IP**: ihl, len, chksum
- **TCP**: dataofs, chksum
- **UDP**: len, chksum
- **ICMP**: chksum
- **TLS**: len, iv, mac, pad, padlen
