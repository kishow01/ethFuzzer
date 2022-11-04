import json

from util import DEFAULT_REPORT_DIR, REPORT_DIR_SIZE_LIMIT
from bridge import Bridge

def get_vulnerability_identifier(trace) -> str:
    return str(trace['pc']) + '_' + trace['op']

class ReentrancyOracle:
    def __init__(self, bridge: Bridge) -> None:
        self.bridge: Bridge = bridge
        self.report = {}

    def setting(self, soruce_code, contract_name, testc_address) -> None:
        self.report['source_code'] = soruce_code
        self.report['contract_name'] = contract_name
        self.report['testc_address'] = testc_address
        self.report['vulnerabilities'] = {}

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
                id = get_vulnerability_identifier(trace)

                if id not in self.report['vulnerabilities']:
                    self.report['vulnerabilities'][id] = {
                        'event': 'reentrancy: state updated after call() function',
                        'trigger': atkc_source_code,
                        'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                        'current': [trace, next_trace],
                        'details': testc_trace
                    }

            if next_trace['depth'] < trace['depth']:
                after_call = True
            elif next_trace['depth'] > trace['depth']:
                after_call = False

    def vulnerability_exists(self):
        return bool(self.report['vulnerabilities'])

    def get_report(self):
        return self.report

    def output_report(self):
        with open(DEFAULT_REPORT_DIR + self.report['testc_address'] + '_reentrancy.json', 'a') as f:
            f.write(json.dumps(self.report, indent = 4))


class InsecureArithmeticOracle:
    def __init__(self, bridge: Bridge, divide_by_zero_detection_disable) -> None:
        self.bridge: Bridge = bridge
        self.divide_by_zero_detection_disable = divide_by_zero_detection_disable
        self.report = {}

    def setting(self, soruce_code, contract_name, testc_address) -> None:
        self.report['source_code'] = soruce_code
        self.report['contract_name'] = contract_name
        self.report['testc_address'] = testc_address
        self.report['vulnerabilities'] = {}

    def detect(self, testc_trace, atkc_source_code, tx_hash) -> None:
        for t_index in range(len(testc_trace['structLogs']) - 1):
            trace = testc_trace['structLogs'][t_index]
            next_trace = testc_trace['structLogs'][t_index + 1]

            if trace['op'] == 'ADD' and trace['pc'] + 1 == next_trace['pc']:
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)
                c = int(next_trace['stack'][len(next_trace['stack']) - 1], 16)
                if c < a:
                    id = get_vulnerability_identifier(trace)

                    if id not in self.report['vulnerabilities']:
                        self.report['vulnerabilities'][id] = {
                            'event': 'addition overflow',
                            'trigger': atkc_source_code,
                            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                            'current': [trace, next_trace],
                            'details': testc_trace
                        }
                    
            elif trace['op'] == 'MUL' and trace['pc'] + 1 == next_trace['pc']:
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)
                c = int(next_trace['stack'][len(next_trace['stack']) - 1], 16)
                if (a != 0) and (c // a != b):
                    id = get_vulnerability_identifier(trace)

                    if id not in self.report['vulnerabilities']:
                        self.report['vulnerabilities'][id] = {
                            'event': 'multiplication overflow',
                            'trigger': atkc_source_code,
                            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                            'current': [trace, next_trace],
                            'details': testc_trace
                        }
            elif trace['op'] == 'SUB':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)
                if b > a:
                    id = get_vulnerability_identifier(trace)

                    if id not in self.report['vulnerabilities']:
                        self.report['vulnerabilities'][id] = {
                            'event': 'substraction overflow',
                            'trigger': atkc_source_code,
                            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                            'current': [trace],
                            'details': testc_trace
                        }
            elif trace['op'] == 'SDIV' or trace['op'] == 'DIV':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)

                if b == 0 and self.divide_by_zero_detection_disable == False:
                    id = get_vulnerability_identifier(trace)

                    if id not in self.report['vulnerabilities']:
                        self.report['vulnerabilities'][id] = {
                            'event': 'division by zero',
                            'trigger': atkc_source_code,
                            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                            'current': [trace],
                            'details': testc_trace
                        }

            elif trace['op'] == 'SMOD' or trace['op'] == 'MOD':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)

                if b == 0 and self.divide_by_zero_detection_disable == False:
                    id = get_vulnerability_identifier(trace)

                    if id not in self.report['vulnerabilities']:
                        self.report['vulnerabilities'][id] = {
                            'event': 'division by zero',
                            'trigger': atkc_source_code,
                            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
                            'current': [trace],
                            'details': testc_trace
                        }
    def vulnerability_exists(self):
        return bool(self.report['vulnerabilities'])

    def get_report(self):
        return self.report
    
    def output_report(self):
        with open(DEFAULT_REPORT_DIR + self.report['testc_address'] + '_insecure_arithmetic.json', 'a') as f:
            f.write(json.dumps(self.report, indent = 4))
        