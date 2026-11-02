"""iptables NFQUEUE rule construction and teardown."""

import logging
import os
import random

logger = logging.getLogger(__name__)

globalQueuesInUse = [0, 1]


def make_iptables_ips(target, args, infected):
    for ip in target.ips:
        try:
            queueNum = 0
            while queueNum in globalQueuesInUse:
                queueNum = random.randrange(2, 65535)
            strQueueNum = str(queueNum)
            strIP = str(ip)
            if args.nat:
                match = f' -m conntrack --ctorigdst {strIP} -j NFQUEUE --queue-num {strQueueNum}'
                toward_c2 = f' -s {infected}' + match        # infected -> C2 (malicious dst)
                toward_infected = f' -d {infected}' + match  # C2 -> infected (malicious src)
            else:
                jump = f' -j NFQUEUE --queue-num {strQueueNum}'
                toward_c2 = f' -s {infected} -d {strIP}' + jump        # infected -> C2
                toward_infected = f' -s {strIP} -d {infected}' + jump  # C2 -> infected
            if args.either_address:
                rule_suffixes = [toward_c2, toward_infected]
            elif args.source_address:
                rule_suffixes = [toward_infected]
            else:
                rule_suffixes = [toward_c2]
            queue_registered = False
            for suffix in rule_suffixes:
                iptablesString = 'iptables -t mangle -I FORWARD' + suffix
                ret = os.system(iptablesString)
                if ret:
                    logger.error(f"'{iptablesString}' failed with exit code {ret}, continuing anyways...")
                    continue
                target.iptablesRules.append(iptablesString)
                target.iptablesTeardown.append('iptables -t mangle -D FORWARD' + suffix)
                logger.debug(f'iptables queue-Number {strQueueNum} successfully built for handle {target.handle}')
                if not queue_registered:
                    globalQueuesInUse.append(queueNum)
                    target.queues.append(queueNum)
                    queue_registered = True
        except Exception as e:
            logger.error(f'Something went wrong in creation of iptables rule for {strIP}, error: {e}')


def teardown_iptables_ips(target):
    rules, target.iptablesTeardown = target.iptablesTeardown, []
    for teardownRule in rules:
        try:
            os.system(teardownRule)
        except Exception as e:
            logger.error(f"failed teardown of '{teardownRule}' Rule with error: {e}, continuing...")
