"""The warden's Target: per-target state and process/queue lifecycle."""

import ast
import functools
import ipaddress
import logging
import multiprocessing
import os
import signal
import threading
import time

from netfilterqueue import NetfilterQueue

import pipeline

logger = logging.getLogger(__name__)

SHUTDOWN_TIMEOUT = 5   # grace period for queue processes and their state cleaner


def signal_shutdown(signum, frame):
    raise KeyboardInterrupt


class Target:
    def __init__(self, config, section):
        self.initSection = section
        self.handle = os.urandom(5).hex()
        self.ips = []
        self.malware = 'unknown'
        self.queues = []
        self.queueProcesses = []
        self.iptablesRules = []
        self.iptablesTeardown = []
        self.manipModes = []
        # per-queue state lives in a pipeline.QueueState, created in queue_process_callback
        if validate_key(config, self.initSection, 'ips'):
            try:
                ips = ast.literal_eval(config[section]['ips'])
            except Exception as e:
                logger.critical(f"targets.ini: [{section}] 'ips' is not a valid list: {e}")
                exit(1)
            for ip in ips:
                try:
                    self.ips.append(ipaddress.ip_address(ip))
                except Exception as e:
                    logger.error(f'skipping invalid IP: {ip}: {e}')
                    continue
        if validate_key(config, self.initSection, 'malware'):
            self.malware = config[section]['malware']

    def print_attr(self):
        logger.debug(f'Init-Section:[{self.initSection}]')
        logger.debug(f'Handle: {self.handle}')
        logger.debug(f'IPS: {self.ips}')
        logger.debug(f'Malware:{self.malware}')
        logger.debug('Created iptables rules: ')
        for rule in self.iptablesRules:
            logger.debug(rule)
        logger.debug(f'Enabled Manipulation Modes: {self.manipModes}')

    def make_process(self, args):
        if not (self.manipModes and self.queues):
            logger.error(f"!! Target '{self.handle}' has either no modes or no queues, no process created.")
            return None
        try:
            proc = multiprocessing.Process(target=self.target_callback, name=str(self.handle), args=(args,))
        except Exception as e:
            logger.error(f"!! Could not create process for '{self.handle}', error:{e}")
            return None
        try:
            proc.start()
        except Exception as e:
            logger.error(f"Could not start process '{proc.name}', error: {e}")
        return proc

    def state_cleanup(self, queue_state, stop, cleaner_timeout):
        logger.debug(f'State cleaner for queue {queue_state.num} up.')
        while not stop.wait(cleaner_timeout):
            try:
                logger.debug(f'Malware/Handle {self.malware}/{self.handle} cleaning states...')
                now = int(time.time())
                deleteList = []
                with queue_state.mutex:
                    for flow_id in queue_state.states:
                        last_occurrence = queue_state.states[flow_id]['timestamp']
                        difference = now - last_occurrence
                        if difference > cleaner_timeout:
                            logger.debug(f'Flow {flow_id} has last seen an occurrence {difference}'
                                        f's ago (cleaner timeout is set to {cleaner_timeout}s). Clearing state.')
                            deleteList.append(flow_id)
                    for flow_id in deleteList:
                        queue_state.states.pop(flow_id)
            except Exception as e:
                logger.error(f'state cleanup failed for queue {queue_state.num}, continuing: {e}')

    def target_callback(self, args):
        signal.signal(signal.SIGINT, signal.SIG_IGN)      # only the main process reacts to Ctrl-C
        signal.signal(signal.SIGTERM, signal_shutdown)    # stop our queue processes when the main process tears down
        try:
            for queue in self.queues:
                try:
                    self.queueProcesses.append(multiprocessing.Process(target=self.queue_process_callback, name=queue, args=(queue, args)))
                except Exception as e:
                    logger.error(f"!! Could not create queue process {queue} for '{self.handle}', error:{e}")
            for process in self.queueProcesses:
                try:
                    process.start()
                except Exception as e:
                    logger.error(f"Could not start queue process {process.name} for '{self.handle}', error: {e}")
                    continue
            for process in self.queueProcesses:
                try:
                    process.join()
                except Exception as e:
                    logger.error(f"Could not join queue process {process.name} for '{self.handle}', error: {e}")
        except KeyboardInterrupt:
            for process in self.queueProcesses:
                if process.is_alive():
                    process.terminate()

    def queue_process_callback(self, queue, args):
        signal.signal(signal.SIGINT, signal.SIG_IGN)      # only the main process reacts to Ctrl-C
        signal.signal(signal.SIGTERM, signal.SIG_DFL)     # die silently when terminated by the target process
        queue_state = pipeline.QueueState(queue)
        logger.debug(f'Hello from callback of queue-process {queue_state.num} for target process {self.handle}')
        for manipDict in self.manipModes:
            if 'on_every' in manipDict['mode_settings']:
                if 'IP' in manipDict['protocols']:
                    logger.warning('Warning: "on_every" setting enabled for a mode which targets IP, make sure this is intentional. Operation: '
                                   + manipDict['mode'])
        stop = threading.Event()
        state_cleaner = threading.Thread(target=self.state_cleanup,
                                         args=(queue_state, stop, args.cleaner_timeout), daemon=True)
        state_cleaner.start()
        nfq = NetfilterQueue()
        if args.sequential_processing:
            callback = self.seqp_callback
        elif args.parallel_processing:
            callback = self.parp_callback
        else:
            logger.critical('No processing method defined.')
            exit(1)
        logger.debug(f'binding to queue {queue_state.num}')
        try:
            try:
                nfq.bind(queue, functools.partial(callback, queue_state), max_len=args.queue_len)
            except Exception as e:
                logger.critical(f'failed to bind NFQUEUE {queue_state.num}: {e}; '
                                'is the queue free and libnetfilter_queue available?')
                exit(1)
            nfq.run(block=True)
        finally:
            stop.set()
            state_cleaner.join(SHUTDOWN_TIMEOUT)

    def seqp_callback(self, queue_state, pkt):
        pipeline.process_packet(self, queue_state, pkt)

    def parp_callback(self, queue_state, pkt):
        pkt.retain()
        queue_state.pool.submit(pipeline.process_packet, self, queue_state, pkt)
        return


def validate_key(config, section, key):
    if config.has_option(section, key):
        if config[section][key] != '':
            return True
    return False
