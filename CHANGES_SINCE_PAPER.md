# Changes Since the Paper

Divergences of the released code from *"A Warden to Analyze and Counter Stegomalware
Activities"* (Gross et al., CUING 2026). Section references point into
that paper; [ARCHITECTURE.md](ARCHITECTURE.md) maps the paper's architecture (Sect. 3) onto the
code.

## Deployment

| Mode | Queue rules match | CLI flag to set |
| --- | --- | --- |
| new default, not present in paper | on-the-wire addresses: `-s {infected} -d {C2}`, and the reverse | none |
| stated in paper (Fig. 2, Sect. 3.2) | pre-NAT destination: `-m conntrack --ctorigdst {C2}` | `--nat` |

## Operations

Beyond Table 1:

- `set` assigns a value to a protocol field directly. It is required for flag fields (`IP.flags`, `TCP.flags`),
  which Scapy exposes as `FlagValue` and which **Replace** cannot edit. Unlike **Replace**, it
  does not clamp to `prot_dict` bounds (Sect. 3.3).

**Inject** takes two settings the paper does not define:

| Setting | Effect |
| --- | --- |
| `index` | position of the first inserted symbol (counted in decimal characters on int/float fields, as in **Replace**), with the remaining symbols following in order; `index == len` appends |
| `inject_value` | symbols to insert as one contiguous sequence at `index`, or at one random position without `index`; mutually exclusive with `amount` |

- **Reset** also sets `window = 512`; the paper copies SEQ/ACK and sets RST only (`Packet.reset`).
- **Inject** cuts the field back to its original length for `HTTP`/`TLS`/`TCP`, warning on
  stderr, where the paper lets Inject exceed the maximum field size (`Packet.injection`).

## Search operations (Sect. 3.3, Table 1)

The pad/truncate step that maintains the original length applies to `HTTP`/`TLS`/`TCP` only
(`packet.py: pad_tcp_based`); other protocols keep the length their edit produces.

- `search_packet_bytes` pads with the byte `0x00`, not the ASCII `'0'` (`0x30`).
  `search_field_string` pads with the `'0'` text character as in the paper.
- `pattern`/`replace_value` accept a `hex:` prefix for arbitrary bytes, avoiding YAML's UTF-8
  decoding of `\xNN` escapes, and the optional boolean `literal: true` `re.escape`s the pattern.
  Regex stays the default (`Packet._decode_bytes`).
