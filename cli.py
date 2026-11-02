"""Command line interface: arguments, startup configuration and shutdown."""

import argparse
import configparser
import ipaddress
import logging
import multiprocessing
import os
import signal
import sys
import time

import yaml

import iptables
from config_validation import validate_config
from packet import setting_is_true
from target import Target, SHUTDOWN_TIMEOUT, signal_shutdown

parser = argparse.ArgumentParser(prog='Web-Tunneling Stego Warden',
                                 description='messes with Layer 4 to disrupt C2 Servers and/or Malware-Instances')


targetMode = parser.add_mutually_exclusive_group()
blockingBool = parser.add_mutually_exclusive_group()

blockingBool.add_argument('--sequential-processing', '-seqp', action='store_true',
                          default=False,
                          help='process one packet in the queue at a time, make all other packets wait')

blockingBool.add_argument('--parallel-processing', '-parp', action='store_true',
                          default=False,
                          help='use a thread from a pool for each arriving packet in the queue, enabling parallel processing. (default)')

targetMode.add_argument('--source-address', '-srcm', action='store_true',
                        help='manipulate packets that have a malicious source address')

targetMode.add_argument('--destination-address', '-dstm', action='store_true',
                        help='manipulate packets that have a malicious destination address')

targetMode.add_argument('--either-address', '-ethm', action='store_true',
                        help='manipulate packets that have a malicious source or destination address (default)')

parser.add_argument('--target-list', '-tl', type=str, default='targets.ini',
                    help='Path to file containing malicious Targets. Default = targets.ini')

parser.add_argument('--log-level', '-ll', default='warning', help='Provide logging level. Default = warning')

parser.add_argument('--malware-config', '-mc', type=str, default='malware.yaml',
                    help='Path to malware -> operation association file. Default = malware.yaml')

parser.add_argument('--nat', action='store_true', default=False,
                    help='NAT mode: match the pre-NAT destination via conntrack '
                         '(warden on a NAT router). Default: non-NAT forwarding.')

parser.add_argument('--queue-len', '-ql', type=int, default=1024,
                    help='Number of packets the kernel may hold in each NFQUEUE before it '
                         'drops further packets. Default = 1024')

parser.add_argument('--cleaner-timeout', '-ct', type=int, default=60,
                    help='Seconds a tracked flow may stay idle before the state cleaner '
                         'evicts it. Default = 60')

targets = []
target_processes = []
logger = logging.getLogger(__name__)


def parse_args(argv=None):
    args = parser.parse_args(argv)
    if args.log_level.upper() not in logging.getLevelNamesMapping():
        parser.error(f"invalid -ll value '{args.log_level}'; use e.g. DEBUG, INFO, WARNING, ERROR, CRITICAL")
    if args.queue_len < 1:
        parser.error(f"invalid -ql value '{args.queue_len}'; the queue length must be at least 1")
    if args.cleaner_timeout < 1:
        parser.error(f"invalid -ct value '{args.cleaner_timeout}'; the cleaner timeout must be at least 1")
    if not (args.either_address or args.source_address or args.destination_address):
        args.either_address = True
    if not (args.sequential_processing or args.parallel_processing):
        args.parallel_processing = True
    return args


def make_targets(args):
    try:
        if not os.path.isfile(args.target_list):
            logger.critical(f'target list not found: {args.target_list}')
            exit(1)
        config = configparser.ConfigParser()
        config.read(args.target_list)
    except Exception as e:
        logger.critical(f'Failed to read target list with: {e}')
        exit(1)
    if not config.has_option('warden', 'infected_ip') or config['warden']['infected_ip'] == '':
        logger.critical("targets.ini: [warden] 'infected_ip' is required")
        exit(1)
    infected = ''
    try:
        infected = str(ipaddress.ip_address(config['warden']['infected_ip']))
    except Exception as e:
        logger.critical(f"targets.ini: invalid [warden] infected_ip: {e}")
        exit(1)
    for section in config.sections():
        if section == 'warden':
            continue
        targets.append(Target(config, section))
    for target in targets:
        iptables.make_iptables_ips(target, args, infected)
    logger.info('Target list processed, targets acquired and iptables for IP targets created')
    if args.log_level.upper() == 'DEBUG':
        os.system('iptables -vnL -t mangle')

def make_target_processes(args):
    for target in targets:
        proc = target.make_process(args)
        if proc is not None:
            target_processes.append(proc)

def associate_modes(malwareConfig):
    for target in targets:
        targetMalware = target.malware
        if targetMalware in malwareConfig:
            if not 'operations' in malwareConfig[targetMalware]:
                logger.error(f'"operations" key not found for malware: {targetMalware}')
                continue
            for operation in malwareConfig[targetMalware]['operations']:
                operation_settings = malwareConfig[targetMalware]['operations'][operation]['settings']
                if 'enabled' in operation_settings and not setting_is_true(operation_settings, 'enabled'):
                    continue
                protocols = malwareConfig[targetMalware]['operations'][operation]['protocols']
                target.manipModes.append(dict(mode=operation, mode_settings=operation_settings,
                                        protocols=protocols))
        if not target.manipModes:
            logger.error(f"!! Warning: Target '{target.handle}'  does not have any associated modes!\n"
                         f"!! This probably means the assigned malware '{targetMalware}' has no enabled or associated modes in malware.yaml\n"
                         'releasing firewall rules')
            iptables.teardown_iptables_ips(target)
        target.print_attr()
        print()

def teardown_all():
    for target in targets:
        logger.debug(f'Tearing down iptables[IP] of target handle {target.handle}')
        iptables.teardown_iptables_ips(target)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)   # shield self while stopping the children
    for process in target_processes:                # only the warden's own children, not the caller's process group
        if process.is_alive():
            process.terminate()                     # targets stop their queue processes on SIGTERM
            process.join(timeout=SHUTDOWN_TIMEOUT)
            if process.is_alive():
                process.kill()


def main(argv=None):
    multiprocessing.set_start_method(method='fork')
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level.upper())
    target_mode = 'either' if args.either_address else 'source' if args.source_address else 'destination'
    processing = 'sequential' if args.sequential_processing else 'parallel'
    logger.debug(f'target-list={args.target_list} malware-config={args.malware_config} '
                 f'target-mode={target_mode} processing={processing} queue-len={args.queue_len} '
                 f'cleaner-timeout={args.cleaner_timeout} '
                 f"nat={'on' if args.nat else 'off'} log-level={args.log_level.upper()}")
    if os.geteuid() != 0:
        logger.critical('the warden creates iptables rules and must run as root')
        sys.exit(1)

    try:
        try:
            if not os.path.isfile(args.malware_config):
                logger.critical(f'malware config (malware to mode association file) not found: {args.malware_config}')
                exit(1)
            malwareFile = open(args.malware_config, 'r')
            malwareConfig = yaml.safe_load(malwareFile)
        except Exception as e:
            logger.critical(f'Something went wrong trying to access or parse {args.malware_config}, error: {e}')
            exit(1)
        validate_config(malwareConfig)
        if args.target_list:
            make_targets(args)
        associate_modes(malwareConfig)
        logger.info('Creating Processes...\n')
        make_target_processes(args)
        # SIGTERM uses the KeyboardInterrupt shutdown path
        signal.signal(signal.SIGTERM, signal_shutdown)
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt received, shutting down...')
        teardown_all()
        sys.exit(0)
    except Exception as e:
        logger.error(f'exiting on error: {e}')
        teardown_all()
        sys.exit(1)
