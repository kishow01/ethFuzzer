import os
import json

from util import DEFAULT_REPORT_DIR, REPORT_DIR_SIZE_LIMIT
from bridge import Bridge

def get_report_dir_size():
    size = 0
    for f in os.scandir(DEFAULT_REPORT_DIR):
        size += os.stat(f).st_size
    return size

class ReentrancyOracle:
    def __init__(self, bridge: Bridge) -> None:
        self.bridge: Bridge = bridge
        self.breaches = []

    def detect(self, testc_trace, atkc_source_code, tx_hash) -> None:
        after_call = False
        for t_index in range(len(testc_trace['structLogs']) - 1):
            trace = testc_trace['structLogs'][t_index]
            next_trace = testc_trace['structLogs'][t_index + 1]

            if trace['op'] == 'STOP':
                after_call = False

            if after_call and (trace['op'] == 'SLOAD' or
                               trace['op'] == 'SSTORE' or
                               trace['op'] == 'MLOAD' or
                               trace['op'] == 'MSTORE'):
                self.breaches.append({
                    'event': 'reentrancy: state updated after call() function',
                    'trigger': atkc_source_code,
                    'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                    'details': [trace, next_trace]
                })

            if next_trace['depth'] < trace['depth']:
                after_call = True
            elif next_trace['depth'] > trace['depth']:
                after_call = False

    def breach_exists(self):
        return bool(self.breaches)

    def get_result(self):
        return self.breaches

    def output_report(self):
        for i in range(len(self.breaches)):
            if get_report_dir_size() > REPORT_DIR_SIZE_LIMIT:
                with open(DEFAULT_REPORT_DIR + '...', 'a') as f:
                    pass
                return

            with open(DEFAULT_REPORT_DIR + self.breaches[i]['transcation']['to'] + '.txt', 'a') as f:
                f.write(json.dumps(self.breaches[i], indent = 4))
                f.write('\n-----------------------------------------\n')


class InsecureArithmeticOracle:
    def __init__(self, bridge: Bridge) -> None:
        self.bridge: Bridge = bridge
        self.breaches = []

    def _twos_complement(self, hex_str: str, bits: int = 16):
        value = int(hex_str, 16)
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def detect(self, testc_trace, atkc_source_code, tx_hash) -> None:
        for t_index in range(len(testc_trace['structLogs']) - 1):
            trace = testc_trace['structLogs'][t_index]
            next_trace = testc_trace['structLogs'][t_index + 1]

            if trace['op'] == 'ADD' and trace['pc'] + 1 == next_trace['pc']:
                a = int(trace['stack'][len(trace['stack']) - 1], 16)
                b = int(trace['stack'][len(trace['stack']) - 2], 16)
                c = int(next_trace['stack'][len(next_trace['stack']) - 1], 16)
                if c < a:
                    self.breaches.append({
                        'event': 'addition overflow',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'details': [trace, next_trace]
                    })
                    
            elif trace['op'] == 'MUL' and trace['pc'] + 1 == next_trace['pc']:
                a = int(trace['stack'][len(trace['stack']) - 1], 16)
                b = int(trace['stack'][len(trace['stack']) - 2], 16)
                c = int(next_trace['stack'][len(next_trace['stack']) - 1], 16)
                if (a != 0) and (c / a != b):
                    self.breaches.append({
                        'event': 'multiplication overflow',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'details': [trace, next_trace]
                    })
            elif trace['op'] == 'SUB':
                a = int(trace['stack'][len(trace['stack']) - 1], 16)
                b = int(trace['stack'][len(trace['stack']) - 2], 16)
                if b > a:
                    self.breaches.append({
                        'event': 'substraction overflow',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'details': [trace]
                    })
            elif trace['op'] == 'SDIV' or trace['op'] == 'DIV':
                a = int(trace['stack'][len(trace['stack']) - 1], 16)
                b = int(trace['stack'][len(trace['stack']) - 2], 16)

                if b == 0:
                    self.breaches.append({
                        'event': 'division by zero',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'details': [trace]
                    })
            elif trace['op'] == 'SMOD' or trace['op'] == 'MOD':
                a = int(trace['stack'][len(trace['stack']) - 1], 16)
                b = int(trace['stack'][len(trace['stack']) - 2], 16)

                if b == 0:
                    self.breaches.append({
                        'event': 'division by zero',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'details': [trace]
                    })

    def breach_exists(self):
        return bool(self.breaches)

    def get_result(self):
        return self.breaches
    
    def output_report(self):
        for i in range(len(self.breaches)):
            if get_report_dir_size() > REPORT_DIR_SIZE_LIMIT:
                with open(DEFAULT_REPORT_DIR + '...', 'a') as f:
                    pass
                return

            with open(DEFAULT_REPORT_DIR + self.breaches[i]['transcation']['to'] + '.txt', 'a') as f:
                f.write(json.dumps(self.breaches[i], indent = 4))
                f.write('\n-----------------------------------------\n')