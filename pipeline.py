"""Per-packet decision: run the configured operations and issue the verdict."""

import concurrent.futures
import logging
import threading

from scapy.layers.inet import IP, TCP, UDP, ICMP

import flow
from packet import OPERATIONS, Packet, operation_base, setting_exists

logger = logging.getLogger(__name__)


class QueueState:
    """State of one queue process: its queue number, its flow table, the lock
    guarding that table (and the config's cross-flow trackers) and its thread pool."""

    def __init__(self, queue):
        self.num = str(queue)
        self.states = {}
        self.mutex = threading.Lock()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=200)


def process_packet(target, queue_state, pkt):
    try:
        raw = pkt.get_payload()
        if len(raw) < 20 or raw[0] >> 4 != 4:
            logger.warning('received a non-IPv4 packet, accepting it unmodified')
            pkt.accept()
            return
        manipPacket = Packet(IP(raw))
        ret = ''
        protocol, field = '', ''
        for manipDict in target.manipModes:
            try:
                for protocol in manipDict['protocols']:
                    for field in manipDict['protocols'][protocol]:
                        if not flow.has_field_and_value(manipPacket, protocol, field):
                            continue
                        mode = manipDict['mode']
                        mode_settings = manipDict['mode_settings']
                        tracking_check = flow.flow_occurrence_check(mode_settings, manipPacket, mode, protocol, field,
                                                                    queue_state)
                        roll_check = flow.roll_check(mode_settings, mode)
                        if flow.should_skip(tracking_check, roll_check):
                            continue
                        if setting_exists(mode_settings, 'trigger_pattern'):
                            if not manipPacket.bytes_pattern(mode_settings['trigger_pattern']):
                                continue
                        method = OPERATIONS[operation_base(mode)]
                        kwargs = {'mode': mode, 'prot': protocol, 'field': field, 'mode_settings': mode_settings}
                        ret = method(manipPacket, **kwargs)
                        if ret == 'drop':
                            pkt.drop()
                            logger.debug('Packet dropped.')
                            return
                        if ret == 'repeat' or flow.skip_rest(mode_settings, mode):
                            finalize(pkt, manipPacket, protocol, field, ret)
                            return
            except Exception as e:
                logger.error(f'Something went wrong starting manip methods: {e}')
        finalize(pkt, manipPacket, protocol, field, ret)
    except Exception as e:
        logger.error(f'process_packet failed, accepting packet unmodified: {e}')
        try:
            pkt.accept()
        except Exception as e2:
            logger.error(f'failed to issue fallback verdict: {e2}')
    return


def finalize(pkt, manipPacket, prot, field, ret):
    if manipPacket.modified:
        # lengths are recomputed on serialization unless the edit targeted them
        if (prot, field) not in (('IP', 'len'), ('UDP', 'len')):
            if 'UDP' in manipPacket.scapyPacket:
                manipPacket.scapyPacket[UDP].len = None
            manipPacket.scapyPacket[IP].len = None
        manipPacket.scapyPacket[IP].chksum = None
        if manipPacket.scapyPacket.haslayer('TCP'):
            manipPacket.scapyPacket[TCP].chksum = None
        if manipPacket.scapyPacket.haslayer('UDP'):
            manipPacket.scapyPacket[UDP].chksum = None
        if manipPacket.scapyPacket.haslayer('ICMP'):
            manipPacket.scapyPacket[ICMP].chksum = None
        pkt.set_payload(bytes(manipPacket.scapyPacket))
    if ret == 'repeat':
        pkt.repeat()
        return
    pkt.accept()
    return
