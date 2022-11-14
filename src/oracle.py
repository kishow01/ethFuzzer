import json

from util import DEFAULT_REPORT_DIR
from logger import Logger, get_vulnerability_identifier


class ReentrancyOracle:
    def __init__(self, logger: Logger) -> None:
        self.logger: Logger = logger

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
                if self.logger.is_vulnerability_exists('reentrancy', id) == False:
                    self.logger.add_vulnerability('reentrancy', id, atkc_source_code, tx_hash, testc_trace, trace)

            if next_trace['depth'] < trace['depth']:
                after_call = True
            elif next_trace['depth'] > trace['depth']:
                after_call = False

class InsecureArithmeticOracle:
    def __init__(self, logger: Logger, divide_by_zero_detection_disable) -> None:
        self.logger: Logger = logger
        self.divide_by_zero_detection_disable = divide_by_zero_detection_disable

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
                    if self.logger.is_vulnerability_exists('arithmetic', id) == False:
                        self.logger.add_vulnerability('arithmetic', id, atkc_source_code, tx_hash, testc_trace, trace, 'addition overflow')                    
            elif trace['op'] == 'MUL' and trace['pc'] + 1 == next_trace['pc']:
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)
                c = int(next_trace['stack'][len(next_trace['stack']) - 1], 16)
                if (a != 0) and (c // a != b):
                    id = get_vulnerability_identifier(trace)
                    if self.logger.is_vulnerability_exists('arithmetic', id) == False:
                        self.logger.add_vulnerability('arithmetic', id, atkc_source_code, tx_hash, testc_trace, trace, 'multiplication overflow')
                   
            elif trace['op'] == 'SUB':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)
                if b > a:
                    id = get_vulnerability_identifier(trace)
                    if self.logger.is_vulnerability_exists('arithmetic', id) == False:
                        self.logger.add_vulnerability('arithmetic', id, atkc_source_code, tx_hash, testc_trace, trace, 'substraction overflow')
            elif trace['op'] == 'SDIV' or trace['op'] == 'DIV':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)

                if b == 0 and self.divide_by_zero_detection_disable == False:
                    id = get_vulnerability_identifier(trace)
                    if self.logger.is_vulnerability_exists('arithmetic', id) == False:
                        self.logger.add_vulnerability('arithmetic', id, atkc_source_code, tx_hash, testc_trace, trace, 'division by zero')
                   
            elif trace['op'] == 'SMOD' or trace['op'] == 'MOD':
                a = int(trace['stack'][-1], 16)
                b = int(trace['stack'][-2], 16)

                if b == 0 and self.divide_by_zero_detection_disable == False:
                    id = get_vulnerability_identifier(trace)
                    if self.logger.is_vulnerability_exists('arithmetic', id) == False:
                        self.logger.add_vulnerability('arithmetic', id, atkc_source_code, tx_hash, testc_trace, trace, 'division by zero')
