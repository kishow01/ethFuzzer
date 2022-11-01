import json
from typing import Tuple, List, Set

from blockchain import Ganache
from bridge import Bridge
from fuzzer import GrammarFuzzer, MutationFuzzer
from scheduler import Variable, Seed, Scheduler
from linker import Linker
from grammar import SOLIDITY_GRAMMAR
from util import DEFAULT_BLOCKCHAIN_KEY_LOCATION, get_pc_op_set, get_opcode_number

class EthFuzzer:
    def __init__(self, 
                 testc_deployer_index: int = 0,
                 atkc_deployer_index: int = 1,
                 scheduler_exponent: int = 3):
        self.testc_deployer_index = testc_deployer_index
        self.atkc_deployer_index = atkc_deployer_index
        self.testc_coverage = set()

        self.bridge: Bridge = Bridge()
        self.linker: Linker = Linker()
        self.gfuzzer: GrammarFuzzer = GrammarFuzzer(SOLIDITY_GRAMMAR)
        self.mfuzzer: MutationFuzzer = None
        self.scheduler: Scheduler = Scheduler(scheduler_exponent)

        # Start ganache server and read key.json
        self.ganache = Ganache()
        self.ganache.start()

        with open(DEFAULT_BLOCKCHAIN_KEY_LOCATION) as file:
            accounts = json.load(file)

        self.address_list = list(accounts['private_keys'].keys())
        self.checksum_address_list = [self.bridge.w3.toChecksumAddress(address) for address in accounts['private_keys'].keys()]
        self.privateKey_of_EOAs = [accounts['private_keys'][pubKey] for pubKey in self.address_list]
        
    def create_testc(self,
                     source_code: str,
                     contract_name: str,
                     compiler_version: str):
        """Compile and deploy smart contract that need to be tested, 'testc' stands for test contract"""
        (self.testc_address, self.testc_abi) = self.bridge.web3_deploy_test_contract(self.privateKey_of_EOAs[self.testc_deployer_index],
                                                                                     source_code,
                                                                                     contract_name,
                                                                                     compiler_version)
        self.testc_pc_op_set = get_pc_op_set(self.bridge.web3_getCode(self.testc_address).hex())
        self.testc_opcode_number = get_opcode_number(self.bridge.web3_getCode(self.testc_address).hex())


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
    
    def run(self, source_code_without_parameters) -> Tuple[Set[str], str]:
        (coverage, source_code) = self.mfuzzer.run(source_code_without_parameters, 
                                    self.bridge, 
                                    self.privateKey_of_EOAs[self.atkc_deployer_index],
                                    self.testc_pc_op_set)
        return (coverage == set(), source_code)

    def get_cumulative_coverage(self) -> Set[str]:
        cumulative_coverage = set() 
        for cov in self.mfuzzer.coverages_seen:
            cumulative_coverage |= cov
        return cumulative_coverage

    def end(self):
        self.ganache.end()
