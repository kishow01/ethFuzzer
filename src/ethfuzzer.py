import os
import json
from typing import Tuple, List, Set
import random

from bridge import Bridge
from fuzzer import GrammarFuzzer, MutationFuzzer
from scheduler import Variable, Seed, Scheduler
from logger import Logger
from linker import Linker
from grammar import SOLIDITY_GRAMMAR
from oracle import ReentrancyOracle, InsecureArithmeticOracle
from util import DEFAULT_BLOCKCHAIN_KEY_LOCATION, get_opcode_number

class EthFuzzer:
    def __init__(self, 
                 testc_deployer_index: int = 0,
                 scheduler_exponent: int = 3,
                 gfuzz_iteration: int = 100,
                 mfuzz_iteration: int = 30,
                 divide_by_zero_detection_disable: bool = False,
                 consolelog_enable: bool = True):
        self.testc_deployer_index = testc_deployer_index
        self.gfuzz_iteration = gfuzz_iteration
        self.mfuzzer_iteration = mfuzz_iteration
        self.consolelog_enable = consolelog_enable

        self.testc_coverage = set()

        self.bridge: Bridge = Bridge()
        if not self.bridge.w3.isConnected():
            raise ConnectionError('Can not connect to blockchain, try ganache-cli for starting your own private chain')

        self.linker: Linker = Linker()
        self.gfuzzer: GrammarFuzzer = GrammarFuzzer(SOLIDITY_GRAMMAR)
        self.mfuzzer: MutationFuzzer = None
        self.scheduler: Scheduler = Scheduler(scheduler_exponent)
        self.logger: Logger = Logger(self.bridge)

        self.insecureArithmeticOracle: InsecureArithmeticOracle = InsecureArithmeticOracle(self.logger, divide_by_zero_detection_disable)
        self.reentrancyOracle: ReentrancyOracle = ReentrancyOracle(self.logger)

        if not os.path.exists(DEFAULT_BLOCKCHAIN_KEY_LOCATION):
            raise FileNotFoundError('No keys.json in blockchain directory')

        with open(DEFAULT_BLOCKCHAIN_KEY_LOCATION) as file:
            accounts = json.load(file)

        self.address_list = list(accounts['private_keys'].keys())
        self.checksum_address_list = [self.bridge.w3.toChecksumAddress(address) for address in accounts['private_keys'].keys()]
        self.privateKey_of_EOAs = [accounts['private_keys'][pubKey] for pubKey in self.address_list]
        

    def create_atkc_via_gfuzz(self) -> Tuple[List[Variable], str]:
        """Create attacker contract via grammar-based fuzzing, atkc stands for attack contract"""
        source_code_without_linking = self.gfuzzer.fuzz()
        (variables, source_code_without_parameters) = self.linker.linking(self.testc_address, self.testc_abi, source_code_without_linking)
        
        return (variables, source_code_without_parameters)

    def init_mfuzzer(self, variables: List[Variable]) -> None:
        seed: Seed = Seed(variables)
        # initialize mutation fuzzer and seed value
        self.mfuzzer = MutationFuzzer(seed, self.scheduler, self.checksum_address_list, self.bridge.w3.toChecksumAddress)
        self.mfuzzer.initialize_all_variable_within_seed()

    def start(self, 
            source_code: str,
            contract_name: str,
            compiler_version: str,
            bytecode: str = '',
            abi = '',
            report_enable: bool = True
            ):
        try:
            # create and deploy test contract
            if bytecode == '':
                (self.testc_abi, testc_bytecode) = self.bridge.web3_compile_test_contract(source_code, contract_name, compiler_version)
            else:
                testc_bytecode = bytecode
                self.testc_abi = abi

            self.testc_address = self.bridge.web3_deploy_test_contract(self.privateKey_of_EOAs[self.testc_deployer_index],
                                                                       self.testc_abi, testc_bytecode)

            if self.consolelog_enable:
                print('[*] test contract deployed at:', self.testc_address)

            return self.run(self.testc_address, self.testc_abi, source_code, contract_name, report_enable)
        except Exception as e:
            if self.consolelog_enable:
                print('EthFuzzer Exception in compile and deploy:', e)
        

    def run(self, testc_address, testc_abi, source_code = '', contract_name = '', report_enable: bool = True):
        insecureArithmeticVulnerabilities = []
        reentrancyVulnerabilities = []

        self.testc_address = testc_address
        self.testc_abi = testc_abi

        self.logger.setting(source_code, contract_name, self.testc_address)

        # overwrite if using main.py
        self.logger.report['testc_address'] = testc_address
        self.testc_abi = testc_abi

        try:
            self.testc_opcode_number = get_opcode_number(self.bridge.web3_getCode(self.testc_address).hex())

            trail = 0
            while trail < self.gfuzz_iteration:
                first_run_being_reverted = False
                if self.consolelog_enable:
                    print('[-] trail #' + str(trail) + ':', end=' ')
                
                # create atk contract and initialize variable
                (variables, source_code_without_parameters) = self.create_atkc_via_gfuzz()
                self.init_mfuzzer(variables)

                # deploy atk contract and execute it by atkc_deployer
                for step in range(0, self.mfuzzer_iteration):
                    (coverage, testc_trace, atkc_source_code, tx_hash) = self.deploy_and_execute_atkc(source_code_without_parameters)
                    if step == 0 and coverage == set():
                        # if first run is reverted, then discard this atk contract and this trail do count
                        first_run_being_reverted = True
                        break

                    if coverage != set():
                        self.oracle_detect(testc_trace, atkc_source_code, tx_hash)

                    if self.consolelog_enable:
                        print('.', end='', flush=True)
                if self.consolelog_enable:
                    print('')

                # calculate overall coverage(cumulative_coverage)
                cumulative_coverage = self.get_cumulative_coverage()
                self.testc_coverage |= cumulative_coverage
                if self.consolelog_enable:
                    print('[-] trail #' + str(trail) + ' coverage:', len(cumulative_coverage) / self.testc_opcode_number)
                    print('[=] testc_coverage so far:', len(self.testc_coverage) / self.testc_opcode_number)

                if first_run_being_reverted == False:
                    trail += 1
            if self.consolelog_enable:
                print('[*] final testc_coverage:', len(self.testc_coverage) / self.testc_opcode_number)
            self.logger.update_coverage(len(self.testc_coverage) / self.testc_opcode_number)

            # Summary
            report = self.logger.get_report()
            insecureArithmeticVulnerabilities = report['vulnerabilities']['arithmetic']
            reentrancyVulnerabilities = report['vulnerabilities']['reentrancy']

            if self.consolelog_enable:
                print('[*] found {} vulnerailities in InsecureArithmeticOracle'.format(len(insecureArithmeticVulnerabilities)))
                print('[*] found {} vulnerailities in ReentrancyOracle'.format(len(reentrancyVulnerabilities)))

            if report_enable:
                if self.consolelog_enable:
                    print('[*] output report')
                self.logger.output_report()
        except Exception as e:
            if self.consolelog_enable:
                print('EthFuzzer Exception in fuzzing:', e)
        finally:
            return (insecureArithmeticVulnerabilities, reentrancyVulnerabilities)

    def deploy_and_execute_atkc(self, source_code_without_parameters) -> Tuple[Set[str], str]:
        atkc_deployer_index = random.randrange(0, len(self.privateKey_of_EOAs))
        (coverage, testc_trace, source_code, tx_hash) = self.mfuzzer.run(source_code_without_parameters, 
                                                                         self.bridge,
                                                                         self.privateKey_of_EOAs[atkc_deployer_index],
                                                                         self.testc_address,
                                                                         self.consolelog_enable)
        return (coverage, testc_trace, source_code, tx_hash)

    def get_cumulative_coverage(self) -> Set[str]:
        cumulative_coverage = set() 
        for cov in self.mfuzzer.coverages_seen:
            cumulative_coverage |= cov
        return cumulative_coverage

    def oracle_detect(self, testc_trace, atkc_source_code: str, tx_hash: str):
        self.insecureArithmeticOracle.detect(testc_trace, atkc_source_code, tx_hash)
        self.reentrancyOracle.detect(testc_trace, atkc_source_code, tx_hash)
        
    def end(self): 
        self.ganache.end()
