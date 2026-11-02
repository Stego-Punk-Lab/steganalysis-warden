import sys
import logging

from packet import OPERATIONS, operation_base

logger = logging.getLogger(__name__)


# Config validators keyed by operation base-name (the part before any '-<n>'
# suffix). Each takes (operation, settings) and returns an error string or None.
# Add an entry here to validate a new operation.
def _validate_replace(operation, settings):
    if 'replace_value' in settings and len(str(settings['replace_value'])) != 1:
        return (operation + ": 'replace_value' must be a single character; use "
                'search_field_string / search_packet_bytes for longer strings')
    return None

def _validate_set(operation, settings):
    if 'value' not in settings:
        return operation + ": 'set' requires a 'value' setting"
    return None

def _validate_injection(operation, settings):
    if 'inject_value' in settings and 'amount' in settings:
        return operation + ": 'inject_value' and 'amount' are mutually exclusive"
    value = settings.get('inject_value')
    if 'inject_value' in settings and (not isinstance(value, str) or not value):
        return operation + ": 'inject_value' must be a non-empty string"
    return None

def _validate_search_settings(operation, settings):
    if not settings.get('pattern'):
        return operation + ": 'pattern' must not be empty"
    if 'replace_value' not in settings:
        return operation + ": requires a 'replace_value' setting"
    return None

def _validate_search_packet_bytes(operation, settings):
    error = _validate_search_settings(operation, settings)
    if error:
        return error
    for key in ('pattern', 'replace_value'):
        value = settings[key]
        if not isinstance(value, str) or not value.startswith('hex:'):
            continue
        try:
            decoded = bytes.fromhex(value[4:].replace(' ', ''))
        except ValueError:
            return operation + f": '{key}' is not valid hex: {value!r}"
        if key == 'pattern' and not decoded:
            return operation + ": 'pattern' must not be empty"
    return None

OPERATION_VALIDATORS = {
    'replace': [_validate_replace],
    'set': [_validate_set],
    'injection': [_validate_injection],
    'search_packet_bytes': [_validate_search_packet_bytes],
    'search_field_string': [_validate_search_settings],
}

# Operations that write the targeted field. Address fields are rejected for
# these: IP src/dst belong to NATed connections so edits are meaningless, and
# scapy falls back to a DNS lookup when handed a malformed address.
FIELD_WRITING_OPERATIONS = {'replace', 'set', 'injection', 'none', 'zero', 'search_field_string'}
PROTECTED_FIELDS = {'IP': ('src', 'dst'), 'ICMP': ('gw', 'addr_mask')}

def _strip_protected_fields(malware, operation, protocols):
    if operation_base(operation) not in FIELD_WRITING_OPERATIONS:
        return
    for protocol, protected in PROTECTED_FIELDS.items():
        fields = protocols.get(protocol)
        if not isinstance(fields, list):
            continue
        dropped = [field for field in fields if field in protected]
        if not dropped:
            continue
        logger.error(f"malware.yaml: {malware}/{operation} cannot target "
                     f"{protocol} {', '.join(dropped)} (address field); ignoring")
        kept = [field for field in fields if field not in protected]
        if kept:
            protocols[protocol] = kept
        else:
            del protocols[protocol]

def validate_config(malwareConfig):
    if not isinstance(malwareConfig, dict):
        logger.critical('malware.yaml did not parse into a malware -> config mapping')
        sys.exit(1)
    errors = []
    for malware, malware_conf in malwareConfig.items():
        operations = (malware_conf or {}).get('operations') or {}
        for operation, op_conf in operations.items():
            if operation_base(operation) not in OPERATIONS:
                errors.append(malware + '/' + operation + ': unknown operation; valid names are '
                              + ', '.join(sorted(OPERATIONS)))
                continue
            if (not isinstance(op_conf, dict)
                    or not isinstance(op_conf.get('protocols'), dict)
                    or not isinstance(op_conf.get('settings'), dict)):
                errors.append(malware + '/' + operation + ": must define 'protocols' and 'settings' mappings")
                continue
            settings = op_conf['settings']
            _strip_protected_fields(malware, operation, op_conf['protocols'])
            for validator in OPERATION_VALIDATORS.get(operation_base(operation), []):
                error = validator(operation, settings)
                if error:
                    errors.append(malware + '/' + error)
    if errors:
        for error in errors:
            logger.critical('malware.yaml config error: ' + error)
        sys.exit(1)
