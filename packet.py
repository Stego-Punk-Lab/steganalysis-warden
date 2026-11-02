import random
import string
import sys
import logging
import re
import time
from protDict import *
from scapy.all import *
load_layer('tls')
load_layer('http')

logger = logging.getLogger(__name__)


def setting_exists(mode_settings, setting_name):
    return setting_name in mode_settings

def setting_is_true(mode_settings, setting_name):
    # boolean settings may be given as YAML bools or as text ('true'/'false', 'yes'/'no', '1'/'0')
    if setting_name not in mode_settings:
        return False
    value = mode_settings[setting_name]
    if isinstance(value, str):
        return value.strip().lower() in ('true', 'yes', 'on', '1')
    return bool(value)

def getReplaceChar(charType, supplied_value=None):
    if supplied_value is not None:
        return type(charType)(supplied_value)
    match charType:
        case int():
            return getInt()
        case str():
            return getChar()
        case _:
            return getBytes()

def getChar():
    return(random.choice(string.ascii_letters + string.digits + string.punctuation))

def getInt():
    return(random.randint(0,9))

def getBytes():
    return(random.randbytes(1))

def getIndex(start,end):
    return random.randint(start, end)

def pad_or_truncate(data, orig_len, fill):
    if len(data) < orig_len:
        data = data + fill * (orig_len - len(data))
    elif len(data) > orig_len:
        data = data[:orig_len]
    return data

def pad_tcp_based(prot, data, orig_len, fill):
    # only the TCP-based protocols keep their original length (Sect. 3.3)
    if prot in ('HTTP', 'TLS', 'TCP'):
        return pad_or_truncate(data, orig_len, fill)
    return data

def cut_injected(prot, value, orig_len):
    # as in the search operations: the TCP-based protocols keep their original length
    # int/float fields count the characters of their decimal text (as in replace).
    # Returns (value, was_cut).
    if prot not in ('HTTP', 'TLS', 'TCP'):
        return value, False
    numeric = isinstance(value, (int, float))
    text = str(value) if numeric else value
    if len(text) <= orig_len:
        return value, False
    text = text[:orig_len]
    if not numeric:
        return text, True
    try:
        return type(value)(text), True
    except ValueError:
        return value, False

def _decode_bytes(spec):
    # 'hex:AA BB' -> raw bytes (spaces ignored); otherwise UTF-8 text
    if isinstance(spec, (bytes, bytearray)):
        return bytes(spec)
    spec = str(spec)
    if spec.startswith('hex:'):
        return bytes.fromhex(spec[4:].replace(' ', ''))
    return spec.encode('utf-8')

# this is a wrapper class for scapy packets, containing the methods for
# manipulation of these
class Packet:
    def __init__(self, payload):
        self.scapyPacket = payload
        self.modified = False

    def bytes_pattern(self, pattern):
        if pattern != None:
            raw_bytes = bytes(self.scapyPacket)
            pattern_bytes = bytes(pattern, 'utf-8')
            matches = list(re.finditer(pattern_bytes, raw_bytes))
            if not matches:
                return False
            else:
                return matches


    def get_occurrences(self, occurrences, matches):
        if 'all' in occurrences:
            return list(range(len(matches)))
        tokens = {'first': 0, 'last': -1}
        return [tokens.get(occurrence, occurrence) for occurrence in occurrences]

    def replace_occurrences(self, haystack, matches, occurrences, offset, replacement):
        # matches/occurrences/offset are resolved by the caller, including their error handling
        orig_len = len(haystack)
        modified = haystack
        displace_mod = 0
        for occurrence in occurrences:
            loc = matches[occurrence].start() + offset + displace_mod
            loc_end = matches[occurrence].end() + offset + displace_mod
            modified = modified[:loc] + replacement + modified[loc_end:]
            displace_mod = len(modified) - orig_len
        return modified

    def field_layer(self, prot, field):
        # own layer of field, scapy resolves through the payload chain
        # (HTTPRequest/HTTPResponse sit below the HTTP marker layer); NoPayload.payload is NoPayload
        layer = self.scapyPacket.getlayer(prot)
        while layer is not None and not isinstance(layer, NoPayload):
            if field in layer.fields or field in layer.default_fields:
                return layer
            layer = layer.payload
        return None

    def drop(self, mode, prot, field, mode_settings):
        return 'drop'

    def reset(self, mode, prot, field, mode_settings):
        if self.scapyPacket[TCP].flags.A:
            new_flags = 'RA'
        else:
            new_flags = 'R'
        new_ack = self.scapyPacket[TCP].ack
        new_seq = self.scapyPacket[TCP].seq
        packet = IP(src = self.scapyPacket[IP].src,
                    dst = self.scapyPacket[IP].dst) / TCP(sport = self.scapyPacket[TCP].sport, dport = self.scapyPacket[TCP].dport,
                    flags= new_flags, window = 512, seq = new_seq, ack = new_ack)
        self.scapyPacket = packet
        self.modified = True
        logger.debug('replaced packet with reset-packet, re-queueing now')
        return 'repeat'

    def latency(self, mode, prot, field, mode_settings):
        ms = 50
        jitter = 0
        if setting_exists(mode_settings, 'ms'):
            ms = mode_settings['ms']
        if setting_exists(mode_settings, 'jitter'):
            tmp = abs(mode_settings['jitter'])
            if tmp != 0:
                jitter = random.randrange(-tmp, tmp)
        delay = abs(ms + jitter)
        logger.debug(f'{int(time.time())} Delaying packet by {delay}ms')
        time.sleep(delay / 1000)

    def replace(self, mode, prot, field, mode_settings):
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        origval = layer.getfieldval(field)
        origval_type = type(origval)
        try:
            # int/float have no len(); their cases edit str(origval)
            origval_len = len(str(origval)) if isinstance(origval, (int, float)) else len(origval)
            if origval_len == 0:
                return
        except Exception as e:
            logger.error('Type Error in replace, passing')
            return
        if setting_exists(mode_settings, 'index'):
            index = mode_settings['index']
            if index not in range(0, origval_len):
                logger.error(f'Index{index} out of range for {prot}/{field}. Defaulting to '
                             f'{origval_len - 1}. Len: {origval_len}')
                index = origval_len - 1
        else:
            index = getIndex(0, origval_len - 1)
        replace_value = mode_settings['replace_value'] if setting_exists(mode_settings, 'replace_value') else None
        match origval:
            case int():
                try:
                    replace_char = str(getReplaceChar(int(), replace_value))
                except (TypeError, ValueError):
                    logger.error(f'replace_value {replace_value!r} is not a valid digit for {prot}/{field}; skipping')
                    return
                # NOTE: index counts digits of str(origval) from the left; a leading zero is dropped.
                tmp = list(str(origval))
                tmp[index] = replace_char
                newval = int(''.join(tmp))
                # prot_dict does not list every protocol (see ARCHITECTURE.md); an
                # unlisted field skips the range check instead of raising KeyError.
                bounds = prot_dict.get(prot, {}).get(field)
                if bounds and not bounds['low'] <= newval <= bounds['high']:
                    if replace_value != None and setting_exists(mode_settings, 'index'):
                        logger.warning(f'Supplied value {replace_value} for mode {mode} on supplied index {index}'
                                       f' has produced a value out of range for field {field}, using highest allowed value.')
                    elif replace_value != None:
                        logger.warning(f'Supplied value {replace_value} for mode {mode} on random index {index}'
                                       f' has produced a value out of range for field {field}, using highest allowed value.'
                                       '\nConsider specifying an "index" to edit for this mode.')
                    else:
                        logger.warning(f'Random value for mode {mode} on random index {index}'
                                       f' has produced a value out of range for field {field}, using highest allowed value.'
                                       '\nConsider specifying an "index" to edit and/or "replace_value" for this mode.')
                    newval = bounds['high']
            case float():
                tmp = list(str(origval))
                tmp[index] = str(getReplaceChar(int(), replace_value))
                newval = float(''.join(tmp))
            case str():
                tmp = list(str(origval))
                tmp[index] = getReplaceChar(str(), replace_value)
                newval = ''.join(tmp)
            case bytes():
                tmp = bytearray(origval)
                tmp[index] = ord(getReplaceChar(str(), replace_value))
                newval = bytes(tmp)
            case _:
                tmp = origval
                tmp[index] = getReplaceChar(bytes(), replace_value)
                newval = tmp
        logger.debug(f'{mode}: oldval: {origval}{origval_type}')
        logger.debug(f'{mode}: newval: {newval}{type(newval)}')
        layer.setfieldval(field, newval)
        self.modified = True

    def set(self, mode, prot, field, mode_settings):
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        value = mode_settings['value']
        origval = layer.getfieldval(field)
        origval_type = type(origval)
        try:
            # flags are a FlagValue (no int/str/bytes match): passed through so
            # scapy accepts a flag string ('RA') or int
            match origval:
                case int():
                    value = int(value)
                case str():
                    value = str(value)
                case bytes():
                    value = value if isinstance(value, bytes) else str(value).encode()
            logger.debug(f'{mode}: oldval: {origval}{origval_type}')
            logger.debug(f'{mode}: newval: {value}{type(value)}')
            layer.setfieldval(field, value)
            self.modified = True
        except Exception as e:
            logger.error(f'Failed to set {prot}/{field} to {value}: {e}')

    def search_packet_bytes(self, mode, prot, field, mode_settings):
        replace_value_bytes = _decode_bytes(mode_settings['replace_value'])
        raw_bytes = bytes(self.scapyPacket)
        pattern_bytes = _decode_bytes(mode_settings['pattern'])
        if setting_is_true(mode_settings, 'literal'):
            pattern_bytes = re.escape(pattern_bytes)
        logger.debug(f'Looking for pattern {pattern_bytes}')
        matches = list(re.finditer(pattern_bytes, raw_bytes))
        if not matches:
            logger.debug(f'No match found in {raw_bytes}')
            return
        orig_len = len(raw_bytes)
        orig_layers = set(self.scapyPacket.layers())
        occurrences = self.get_occurrences(mode_settings['occurrences'], matches)
        offset = int(mode_settings['offset']) if setting_exists(mode_settings, 'offset') else 0
        try:
            modded_bytes = self.replace_occurrences(raw_bytes, matches, occurrences, offset,
                                                    replace_value_bytes)
        except Exception as e:
            logger.error(f'Failed byteop replacement with error: {e}')
            return
        logger.debug(raw_bytes)
        logger.debug(modded_bytes)
        modded_bytes = pad_tcp_based(prot, modded_bytes, orig_len, b'\x00')
        new_pkt = IP(modded_bytes)
        new_layers = set(new_pkt.layers())
        introduced = new_layers - orig_layers
        lost = orig_layers - new_layers
        if introduced & {Raw, Padding} or lost:
            logger.error('search_packet_bytes: edit left the packet unparseable '
                         '(layer structure changed); keeping original. Use '
                         'search_field_string for structured protocol fields.')
            return
        self.scapyPacket = new_pkt
        self.modified = True

    def search_field_string(self, mode, prot, field, mode_settings):
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        origval = layer.getfieldval(field)
        origval_type = type(origval)
        replace_value = mode_settings['replace_value']
        if origval_type is bytes:
            origval_str = origval.decode('utf-8')
        else:
            origval_str = str(origval)
        orig_len = len(origval_str)
        matches = list(re.finditer(str(mode_settings['pattern']), origval_str))
        if not matches:
            logger.debug(f'No match found in {origval_str}')
            return
        occurrences = self.get_occurrences(mode_settings['occurrences'], matches)
        offset = int(mode_settings['offset']) if setting_exists(mode_settings, 'offset') else 0
        newval_str = self.replace_occurrences(origval_str, matches, occurrences, offset, replace_value)
        newval_str = pad_tcp_based(prot, newval_str, orig_len, '0')
        logger.debug(f'{mode}: oldval: {origval}{origval_type}')
        logger.debug(f'{mode}: newval: {newval_str}{type(newval_str)}')
        layer.setfieldval(field, newval_str)
        self.modified = True

    def injection(self, mode, prot, field, mode_settings):
        provided = mode_settings['inject_value'] if setting_exists(mode_settings, 'inject_value') else None
        if provided is not None and setting_exists(mode_settings, 'amount'):
            logger.error(f'Mode {mode}: "inject_value" and "amount" are mutually exclusive, skipping')
            return
        # one insertion per character of inject_value, in order; otherwise `amount` random symbols
        symbols = list(str(provided)) if provided is not None else None
        if symbols is not None:
            amount = len(symbols)
        elif not setting_exists(mode_settings, 'amount'):
            amount = 1
        else:
            amount = mode_settings['amount']
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        startval = layer.getfieldval(field)
        if isinstance(startval, FlagValue):
            print(f'Cannot inject into flag field {prot}/{field}; use the "set" operation instead.', file=sys.stderr)
            return
        orig_len = len(startval) if isinstance(startval, (str, bytes, list)) else len(str(startval))
        index = None
        if setting_exists(mode_settings, 'index'):
            index = mode_settings['index']
            if not 0 <= index <= orig_len:
                logger.error(f'Index {index} out of range for {prot}/{field}. Defaulting to '
                             f'{orig_len}. Len: {orig_len}')
                index = orig_len
        for cycle in range(0, amount):
            origval = layer.getfieldval(field)  # field conversion (DNS name re-adds root dot) can shift later inserts
            # insertion position: `index` if given, else a random one. A supplied value is
            # inserted as one contiguous sequence; `amount` random symbols are placed
            # individually, so each one lands at its own random position.
            symbol = symbols[cycle] if symbols is not None else None
            sequence = symbols is not None
            try:
                match origval:
                    case int():
                        origvalNumList = list(str(origval))
                        if index is None and sequence:
                            index = getIndex(0, len(origvalNumList))
                        loc = index + cycle if index is not None else getIndex(0, len(origvalNumList))
                        origvalNumList.insert(loc, symbol if symbol is not None else str(getInt()))
                        newval = int(''.join(origvalNumList))
                    case str():
                        if index is None and sequence:
                            index = getIndex(0, len(origval) + 1)
                        loc = index + cycle if index is not None else getIndex(0, len(origval) + 1)
                        newval = origval[:loc] + (symbol if symbol is not None else getChar()) + origval[loc:]
                    case float():
                        origval_str = str(origval)
                        dotloc = origval_str.find('.')
                        origval_dotless = origval_str.replace('.', '')
                        if index is None and sequence:
                            index = getIndex(0, len(origval_dotless))
                        loc = index + cycle if index is not None else getIndex(0, len(origval_dotless))
                        digit = symbol if symbol is not None else str(getInt())
                        newval_dotless = origval_dotless[:loc] + digit + origval_dotless[loc:]
                        if dotloc == -1:
                            newval = float(newval_dotless)
                        else:
                            newval = float(newval_dotless[:dotloc] + '.' + newval_dotless[dotloc:])
                    case list():
                        newval = origval
                        if index is None and sequence:
                            index = getIndex(0, len(origval))
                        loc = index + cycle if index is not None else getIndex(0, len(origval))
                        newval.insert(loc, symbol if symbol is not None else getChar())
                    case _:
                        origvalType = type(origval)
                        origval_bytes = bytes(origval)
                        if index is None and sequence:
                            index = getIndex(0, len(origval_bytes)+1)
                        loc = index + cycle if index is not None else getIndex(0, len(origval_bytes)+1)
                        insert_bytes = symbol.encode('utf-8') if symbol is not None else getBytes()
                        newval_bytes = origval_bytes[:loc] + insert_bytes + origval_bytes[loc:]
                        newval = type(origvalType())(newval_bytes)
            except Exception as e:
                logger.error(f'Error during packet manipulation in mode injection: {e}')
                continue
            try:
                layer.setfieldval(field, newval)
                self.modified = True
            except Exception as e:
                print(f'Catastrophic Failure during assigning of new value. Did you produce an invalid value? Error: {e}', file=sys.stderr)
        value, cut = cut_injected(prot, layer.getfieldval(field), orig_len)
        if cut:
            try:
                layer.setfieldval(field, value)
            except Exception as e:
                logger.error(f'Failed to cut injected {prot}/{field} back to length {orig_len}: {e}')
                return
            print(f'Injection into {prot}/{field} exceeded the original length of {orig_len}; '
                  'field cut short to keep the packet length valid.', file=sys.stderr)
        finalval = layer.getfieldval(field)
        logger.debug(f'{mode}: oldval: {startval}{type(startval)}')
        logger.debug(f'{mode}: newval: {finalval}{type(finalval)}')
        return

    def none(self, mode, prot, field, mode_settings):
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        layer.setfieldval(field, None)
        self.modified = True
        logger.debug(f'set {field} to None')

    def zero(self, mode, prot, field, mode_settings):
            layer = self.field_layer(prot, field)
            if layer is None:
                return
            origval = layer.getfieldval(field)
            try:
                match origval:
                    case FlagValue():
                        layer.setfieldval(field, 0)
                    case int():
                        layer.setfieldval(field, 0)
                    case str():
                        layer.setfieldval(field, '0')
                    case float():
                        layer.setfieldval(field, 0.0)
                    case list():
                        layer.setfieldval(field, [0])
                    case _:
                        origvalType = type(origval)
                        layer.setfieldval(field, type(origvalType())(0))
                self.modified = True
                logger.debug(f'set {field} to typecast 0')
            except Exception as e:
                print(f'failed to zero field {field} in protocol {prot}, Error: {e}', file=sys.stderr)

    def repeat(self, mode, prot, field, mode_settings):
        logger.debug('Repeating packet')
        return 'repeat'

    def silent_accept(self, mode, prot, field, mode_settings):
        return

    def print_field_as_string(self, mode, prot, field, mode_settings):
        layer = self.field_layer(prot, field)
        if layer is None:
            return
        value = layer.getfieldval(field)
        print(f'Print as String {prot} {field}: Value: {value}')
        logger.debug(f'Type of previous: {type(value)}')

    def print_packet_as_bytes(self, mode, prot, field, mode_settings):
        print('Packet_as_bytes: ', end= '')
        print(bytes(self.scapyPacket))


# Dispatch table for the operation names used in malware.yaml. Config keys are
# '<operation>' or '<operation>-<suffix>'; the suffix only makes the key unique.
OPERATIONS = {
    'drop': Packet.drop,
    'reset': Packet.reset,
    'latency': Packet.latency,
    'replace': Packet.replace,
    'set': Packet.set,
    'search_packet_bytes': Packet.search_packet_bytes,
    'search_field_string': Packet.search_field_string,
    'injection': Packet.injection,
    'none': Packet.none,
    'zero': Packet.zero,
    'repeat': Packet.repeat,
    'silent_accept': Packet.silent_accept,
    'print_field_as_string': Packet.print_field_as_string,
    'print_packet_as_bytes': Packet.print_packet_as_bytes,
}


def operation_base(mode):
    return mode.split('-', 1)[0]
