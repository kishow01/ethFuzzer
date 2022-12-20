import json

from util import DEFAULT_REPORT_DIR

def get_vulnerability_identifier(trace) -> str:
    return str(trace['pc']) + '_' + trace['op']

class Logger: 
    def __init__(self, bridge):
        self.report_dir = DEFAULT_REPORT_DIR
        self.bridge = bridge
        self.report = {}

    def setting(self, testc_source_code, testc_contract_name, testc_address):
        self.report['source_code'] = testc_source_code
        self.report['contract_name'] = testc_contract_name
        self.report['testc_address'] = testc_address
        self.report['coverage'] = 0.0
        self.report['vulnerabilities'] = {
            'reentrancy': {},
            'arithmetic': {}
        }
    
    def is_vulnerability_exists(self, type, vulnerability_identifier):
        return vulnerability_identifier in self.report['vulnerabilities'][type]

    def add_vulnerability(self, type, vulnerability_identifier, atkc_source_code, tx_hash, testc_trace, trace, subtype = ''):
        event = 'unknown'
        if type == 'reentrancy':
            event = 'reentrancy: state updated after call() function'
        elif type == 'arithmetic':
            if subtype == 'addition overflow':
                event = 'addition overflow'
            elif subtype == 'multiplication overflow':
                event = 'multiplication overflow'
            elif subtype == 'substraction overflow':
                event = 'substraction overflow'
            elif subtype == 'division by zero':
                event = 'division by zero'
            
        self.report['vulnerabilities'][type][vulnerability_identifier] = {
            'event': event,
            'atkc_source_code': atkc_source_code,
            'transcation': self.bridge.eth_getTransactionByHash(tx_hash),
            'trigger': [trace],
            'details': testc_trace
        }
    
    def update_coverage(self, cov: int):
        self.report['coverage'] = cov

    def get_report(self):
        return self.report

    def output_report(self):
        with open(DEFAULT_REPORT_DIR + self.report['testc_address'] + '.json', 'a') as f:
            f.write(json.dumps(self.report, indent = 4))