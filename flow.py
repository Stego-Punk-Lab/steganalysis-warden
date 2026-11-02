"""Per-packet flow tracking: field/value gate, chance rolls and occurrence counting."""

import logging
import random
import time

from packet import setting_is_true

logger = logging.getLogger(__name__)


def has_field_and_value(manipPacket, protocol, field):
    layer = manipPacket.field_layer(protocol, field)
    return layer is not None and layer.getfieldval(field) is not None


def roll_check(mode_settings, mode):
    if 'chance' in mode_settings:
        skip_chance = mode_settings['chance']
        roll = random.randrange(0, 100)
        if roll < skip_chance:
            logger.debug(f'Packet got a lucky roll and is skipped.({roll}/{skip_chance}); Mode: {mode}')
            return True
        else:
            logger.debug(f'Packet got unlucky and will be edited. ({roll}/{skip_chance}); Mode: {mode}')
            return False
    else:
        return None


def skip_rest(mode_settings, mode):
    if setting_is_true(mode_settings, 'skip_rest'):
        logger.debug(f'Skipping all modes after {mode}')
        return True
    return False


def make_flow_id(port_a, port_b):
    x, y = sorted((port_a, port_b))
    return (x << 16) | y


def flow_occurrence_check(mode_settings, manipPacket, mode, prot, field, queue_state):
    if 'on_every' in mode_settings:
        reassembled_id = None
        match prot:
            case 'TCP' | 'HTTP' | 'TLS':
                protocol = 'TCP'
            case 'UDP' | 'DNS' | 'DNSQR' | 'DNSRR' | 'DNSRROPT':
                protocol = 'UDP'
            case _:
                protocol = 'IP'
        if not protocol == 'IP':
            try:
                sport = manipPacket.scapyPacket[protocol].sport
                dport = manipPacket.scapyPacket[protocol].dport
                flow_id = str(make_flow_id(sport, dport))
            except Exception as e:
                logger.error(f'Failed getting ports with error: {e}')
                return None
        else:
            # this isn't great, since the IPs will always be the same, but queue Number will serve as seperator
            # but 'do x to every IP packet'  should be implemented for basic dropping or latency
            num_str = (str(manipPacket.scapyPacket['IP'].src) + str(manipPacket.scapyPacket['IP'].dst)).replace('.', '')
            flow_id_int = 0
            for digit in num_str:
                flow_id_int += int(digit)
            flow_id = str(flow_id_int)
            if prot == 'ICMP':
                flow_id = flow_id + '-ICMP'
        flow_id = flow_id + '-' + mode + prot + field
        on_every = mode_settings['on_every']
        with queue_state.mutex:
            if flow_id not in queue_state.states:
                queue_state.states.update({flow_id: {'tracker': 0, 'timestamp': int(time.time())}})
                logger.debug(f'Assuming new flow mode with id {flow_id} in queue {queue_state.num}')
            tracker = queue_state.states[flow_id]['tracker'] + 1
            queue_state.states[flow_id]['timestamp'] = int(time.time())
            if tracker >= on_every:
                logger.debug(f'Flow with ID {flow_id} reached {on_every} occurrence(s), packet will be edited.')
                queue_state.states[flow_id]['tracker'] = 0
                return False
            logger.debug(f'Observed an occurrence for mode-flow {flow_id}, striking in '
                         f'{on_every - tracker} occurrence(s)')
            queue_state.states[flow_id]['tracker'] = tracker
            return True
    elif 'on_every_cross_flow' in mode_settings:
        on_every = mode_settings['on_every_cross_flow']
        with queue_state.mutex:
            tracker = mode_settings.get('tracker', 0) + 1
            if tracker >= on_every:
                logger.debug(f'Cross flow tracker for mode {mode} striking now.')
                mode_settings['tracker'] = 0
                return False
            logger.debug(f'Cross flow tracker for mode {mode} striking in {on_every - tracker}')
            mode_settings['tracker'] = tracker
            return True
    else:
        return None


def should_skip(tracking_check, roll_check):
    if tracking_check is None:
        return roll_check is True
    if tracking_check is True:
        return roll_check is not False
    # tracking_check is False: occurrence tracking says apply, which beats any skip
    if roll_check is True:
        logger.debug('Tracking determines packet lucky roll will be ignored')
    return False
