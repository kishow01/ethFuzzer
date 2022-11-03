from typing import Union, Tuple, Dict, List, Set, Optional, Callable, Any

import random
import re

from util import szabo_to_wei, finney_to_wei
from type import Option, Expansion, Grammar, DerivationTree
from mutator import DeletionMutator, InsertionMutator, FlipMutator, AddressMutator, IntMutator
from blockchain import Ganache
from scheduler import Scheduler, Seed
from bridge import Bridge
from grammar import SOLIDITY_GRAMMAR

START_SYMBOL = '<start>'
RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

def nonterminals(expansion):
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return RE_NONTERMINAL.findall(expansion)

def isnonterminal(s):
    return RE_NONTERMINAL.match(s)

def all_terminals(tree: DerivationTree) -> str:
    (symbol, children) = tree
    if children is None:
        return symbol
    if len(children) == 0:
        return symbol
    return ''.join([all_terminals(c) for c in children])

def tree_to_string(tree: DerivationTree):
    symbol, children, *_ = tree
    if children:
        return ''.join(tree_to_string(c) for c in children)
    else:
        return '' if isnonterminal(symbol) else symbol

def exp_string(expansion: Expansion) -> str:
    if isinstance(expansion, str):
        return expansion
    return expansion[0]

def expansion_to_children(expansion: Expansion) -> List[DerivationTree]:
    expansion = exp_string(expansion)
    assert isinstance(expansion, str)

    if expansion == '':
        return [('', [])]

    strings = re.split(RE_NONTERMINAL, expansion)
    return [(s, None) if isnonterminal(s) else (s, []) for s in strings if len(s) > 0]

def expansion_key(symbol: str, 
                  expansion: Union[Expansion, DerivationTree, List[DerivationTree]]) -> str:
    """
    Conert (symbol, 'expansion') pair into a key "SYMBOL -> EXPANSION".
    'expansion' can be an expansion string, a derivation tree, or a list of derivations tree.
    """
    if isinstance(expansion, Tuple):
        expansion, _ = expansion

    if not isinstance(expansion, str):
        children = expansion
        expansion = all_terminals((symbol, children))

    assert isinstance(expansion, str)

    return symbol + ' -> ' + expansion

class MutationFuzzer:
    def __init__(self, 
                  init_seed: Seed,
                 scheduler: Scheduler,
                 checksum_address_list: List[str],
                 to_checksum_function: Callable) -> None:
        self.seeds: List[Seed] = [ init_seed ]
        self.scheduler = scheduler
        self.checksum_address_list = checksum_address_list
        self.inputs: List[str] = []
        self.to_checksum_function = to_checksum_function
        self.coverages_seen = set()
        self.population = []

    def initialize_all_variable_within_seed(self) -> None:
        assert len(self.seeds) == 1

        for variable in self.seeds[0].variable_list:
            if 'int' in variable.type:
                # Treat variable.data as an integer
                if 'uint' in variable.type:
                    variable.data = random.randrange(0, pow(2, int(variable.type.replace('uint', ''))))
                else:
                    variable.data = random.randrange(-1 * pow(2, int(variable.type.replace('int', '') - 1)), pow(2, int(variable.type.replace('int', '') - 1)))
            elif 'address' in variable.type:
                # Treat variable.data as an address
                variable.data = random.choice(self.checksum_address_list)
            else:
                # Treat variable.data as a string
                variable.data = ''

    def mutate(self, seed: Seed) -> str:
        mutators = [
            DeletionMutator(),
            InsertionMutator(),
            FlipMutator()
        ]

        address_mutator = AddressMutator(self.checksum_address_list, self.to_checksum_function)

        # Randomly choose varaible for seed, the probability of being selected is 0.3
        for variable in seed.variable_list:
            if random.randrange(0, 10) <= 3:
                mutator = None
                if 'int' in variable.type:
                    mutator = IntMutator(variable.type)
                elif 'address' in variable.type:
                    mutator = address_mutator
                else:
                    mutator = random.choice(mutators)

                variable.data = mutator.mutate(variable.data)

        return seed

    def _create_candidate(self) -> Seed:
        candidate = self.scheduler.choose(self.population)
        candidate = self.mutate(candidate)

        return candidate

    def fuzz(self) -> Seed:
        if len(self.seeds):
            choosen_seed = self.seeds.pop()
        else:
            choosen_seed = self._create_candidate()

        return choosen_seed

    def _filling_atkcode_with_seed(self, source_code: str, seed: Seed) -> str:
        for variable in seed.variable_list:
            source_code = source_code.replace(variable.label, str(variable.data), 1)
        return source_code

    def _delete_unessential_opcode_from_trace(self, trace, testc_address_last_4bytes):
        new_trace = {
            'gas': trace['gas'],
            'returnValue': trace['returnValue'],
            'structLogs': []
        }

        # store the opcode in the list temporarily.
        # Since its possible that current call is being revert,
        # Once all logs have been recorded, check if any revert exists
        # STOP, REVERT, RETURN THESE THREE OPCODE HAVE NOTHING TO DO WITH REDUCING DEPTH
        level_in_testc = {
            0: False
        }
        for index in range(len(trace['structLogs']) - 1):
            log = trace['structLogs'][index]
            next_log = trace['structLogs'][index + 1]
            current_level = log['depth']
            if level_in_testc[current_level]:
                new_trace['structLogs'].append(log)

            if (log['op'] == 'CALL' or log['op'] == 'CALLCODE' or log['op'] == 'DELEGATECALL') and testc_address_last_4bytes.lower() in log['stack'][len(log['stack']) - 2]:
                if log['pc'] + 1 != next_log['pc']:
                    level_in_testc[next_log['depth']] = True
            elif (log['op'] == 'CALL' or log['op'] == 'CALLCODE' or log['op'] == 'DELEGATECALL') and testc_address_last_4bytes.lower() not in log['stack'][len(log['stack']) - 2]:
                level_in_testc[next_log['depth']] = False

        return new_trace

    def _remove_reverted_code(self, testc_trace):
        # Delete reverted code from log_contain_reverted_code
        # I dont know how to write python :(
        # dont allow to delete item in iteration, so i create a new list
        new_trace = {
            'gas': testc_trace['gas'],
            'returnValue': testc_trace['returnValue'],
            'structLogs': []
        }

        newLogs = []
        for i in range(len(testc_trace['structLogs'])):
            newLogs.append(testc_trace['structLogs'][i])
            if testc_trace['structLogs'][i]['op'] == 'REVERT':
                j = i
                # remove item from i to 0, until log[j]['depth'] < log[i]['depth']
                while testc_trace['structLogs'][i]['depth'] <= testc_trace['structLogs'][j]['depth']:
                    if testc_trace['structLogs'][j] in newLogs:
                        newLogs.remove(testc_trace['structLogs'][j])
                    j -= 1
                    if j == 0:
                        new_trace['structLogs'] = []
                        return new_trace
        new_trace['structLogs'] = newLogs
        return new_trace

    def _get_coverage(self, trace) -> Set[str]:
        coverage: Set[str] = set()
        for log in trace['structLogs']:
            coverage.add(str(log['pc']) + '_' + log['op'])
        return coverage

    def run(self, source_code: str, bridge: Bridge, sender_privatekey: str, testc_address: str):
        choosen_seed = self.fuzz()

        # filling $PARAMETER_x$ with appropriate variable in choosen_seed
        source_code = self._filling_atkcode_with_seed(source_code, choosen_seed)

        # Deploy atkc
        try:
            (atkc_address, atkc_abi) = bridge.web3_deploy_attacker_contract(sender_privatekey, source_code)
        except Exception as e:
            print('EVM Runtime Exception in deploy atkc:', e)
            return (set(), '', source_code, '')

        # Execute atkc
        stateMutability = [abi for abi in atkc_abi if 'name' in abi and abi['name'] == 'test'][0]['stateMutability']
        if stateMutability == 'payable':
            value = random.randint(szabo_to_wei(1), finney_to_wei(1))
        else:
            value = 0
        
        try:
            tx_hash = bridge.web3_call(atkc_address, sender_privatekey, value)
        except Exception as e:
            print('EVM Runtime Exception in execute atkc:', e)
            return (set(), '', source_code, '')

        # tracing transaction to get coverage information
        # coverage information is first processed to remove opcode that are not part of this smart contract to calculate coverage
        trace = bridge.debug_traceTransaction(tx_hash)
        testc_trace = self._delete_unessential_opcode_from_trace(trace, testc_address[-8:])
        testc_trace_without_reverted = self._remove_reverted_code(testc_trace)

        coverage = self._get_coverage(testc_trace_without_reverted)
        path_id = self.scheduler.getPathID(coverage)
        self.scheduler.update_path_frequency(path_id)

        # if discover new coverage, add choosen_seed into population
        new_coverage = frozenset(coverage)

        if new_coverage not in self.coverages_seen:
            seed = Seed(choosen_seed.variable_list)
            seed.coverage = coverage
            self.coverages_seen.add(new_coverage)
            self.population.append(seed)
        
        return (coverage, testc_trace_without_reverted, source_code, tx_hash)
        

class GrammarFuzzer:
    def __init__(self,
                 grammar: Grammar,
                 start_symbol: str = START_SYMBOL,
                 min_nonterminals: int = 5,
                 max_nonterminals: int = 10,
                 log: Union[bool, int] = False) -> None:
        self.grammar = grammar
        self.start_symbol = start_symbol
        self.min_nonterminals = min_nonterminals
        self.max_nonterminals = max_nonterminals
        self.log = log
        self.covered_expansions: Set[str] = set()

    def _init_tree(self) -> DerivationTree:
        return (self.start_symbol, None)

    def _choose_node_expansion(self, 
                               node: DerivationTree,
                               children_alternatives: List[List[DerivationTree]]) -> int:
        (symbol, children) = node
        new_coverages = self.new_coverages(node, children_alternatives)

        if new_coverages is None:
            # All expansions covered - randomly choose
            return self._choose_covered_node_expansion(node, children_alternatives)

        max_new_coverage = max(len(cov) for cov in new_coverages)
        children_with_max_new_coverage = [c for (i, c) in enumerate(children_alternatives)
                                          if len(new_coverages[i]) == max_new_coverage]

        index_map = [i for (i, c) in enumerate(children_alternatives)
                     if len(new_coverages[i]) == max_new_coverage]
        
        # Select random expansion from children with max coverage
        new_children_index = self._choose_uncovered_node_expansion(node, children_with_max_new_coverage)
        new_children = children_with_max_new_coverage[new_children_index]

        key = expansion_key(symbol, new_children)

        if self.log:
            print('Now Covered:', key)
        self.covered_expansions.add(key)

        return index_map[new_children_index]

    def _choose_uncovered_node_expansion(self, 
                                        node: DerivationTree,
                                        children_alternatives: List[List[DerivationTree]]) -> int:
        (symbol, children) = node
        index = random.randrange(0, len(children_alternatives))
        self.add_coverage(symbol, children_alternatives[index])
        return index

    def _choose_covered_node_expansion(self, 
                                      node: DerivationTree,
                                      children_alternatives: List[List[DerivationTree]]) -> int:
        (symbol, children) = node
        index = random.randrange(0, len(children_alternatives))
        self.add_coverage(symbol, children_alternatives[index])
        return index

    def _missing_expansion_coverage(self) -> Set[str]:
        return self.max_expansion_coverage() - self.expansion_coverage()

    def _expansion_to_children(self, expansion: Expansion) -> List[DerivationTree]:
        return expansion_to_children(expansion)

    def _process_chosen_children(self, chosen_children: List[DerivationTree], expansion: Expansion) -> List[DerivationTree]:
        return chosen_children

    
    def _expand_node_randomly(self, node: DerivationTree) -> DerivationTree:
        (symbol, children) = node
        assert children is None

        if self.log:
            print('Expanding \'{}\' randomly...'.format(all_terminals(node)))

        expansions = self.grammar[symbol]
        children_alternatives: List[List[DerivationTree]] = [
            self._expansion_to_children(expansion) for expansion in expansions
        ]

        index = self._choose_node_expansion(node, children_alternatives)
        choose_children = children_alternatives[index]

        choose_children = self._process_chosen_children(choose_children, expansions[index])

        return (symbol, choose_children)

    def _possible_expansions(self, node: DerivationTree) -> int:
        (symbol, children) = node
        if children is None:
            return 1
        return sum(self._possible_expansions(c) for c in children)

    def _any_possible_expansions(self, node: DerivationTree) -> bool:
        (symbol, children) = node
        if children is None:
            return True

        return any(self._any_possible_expansions(c) for c in children)

    def _choose_tree_expansion(self,
                              tree: DerivationTree,
                              children: List[List[DerivationTree]]) -> int:
        return random.randrange(0, len(children))

    def _expand_tree_once(self, tree: DerivationTree) -> DerivationTree:
        (symbol, children) = tree
        if children is None:
            return self.expand_node(tree)

        expandable_children = [c for c in children if self._any_possible_expansions(c)]
        index_map = [i for (i, c) in enumerate(children) if c in expandable_children]

        child_to_be_expanded = self._choose_tree_expansion(tree, expandable_children)

        children[index_map[child_to_be_expanded]] = self._expand_tree_once(expandable_children[child_to_be_expanded])

        return tree


    def _symbol_cost(self, symbol: str, seen: Set[str] = set()) -> Union[int, float]:
        expansions = self.grammar[symbol]
        return min(self._expansion_cost(e, seen | {symbol}) for e in expansions)

    def _expansion_cost(self, expansion: Expansion, seen: Set[str] = set()) -> Union[int, float]:
        symbols = nonterminals(expansion)
        if len(symbols) == 0:
            return 1
        if any(s in seen for s in symbols):
            return float('inf')

        return sum(self._symbol_cost(s, seen) for s in symbols) + 1

    def _expand_node_by_cost(self, node: DerivationTree, choose: Callable = min) -> DerivationTree:
        (symbol, children) = node
        assert children is None

        expansions = self.grammar[symbol]
        children_alternatives_with_cost = [(self._expansion_to_children(expansion),
                                            self._expansion_cost(expansion, {symbol}),
                                            expansion) for expansion in expansions]

        costs = [cost for (child, cost, expansion) in children_alternatives_with_cost]
        chosen_cost = choose(costs)

        children_with_chosen_cost = [child for (child, child_cost, _) 
                                     in children_alternatives_with_cost 
                                     if child_cost == chosen_cost]
        expansion_with_chosen_cost = [expansion for (_, child_cost, expansion)
                                     in children_alternatives_with_cost
                                     if child_cost == chosen_cost]

        index = self._choose_node_expansion(node, children_with_chosen_cost)

        chosen_children = children_with_chosen_cost[index]
        chosen_expansion = expansion_with_chosen_cost[index]
        chosen_children = self._process_chosen_children(chosen_children, chosen_expansion)

        return (symbol, chosen_children)

    def _expand_node_min_cost(self, node: DerivationTree) -> DerivationTree:
        if self.log:
            print('Expanding {} by min cost...'.format(all_terminals(node)))

        return self._expand_node_by_cost(node, min)

    def _expand_node_max_cost(self, node: DerivationTree) -> DerivationTree:
        if self.log:
            print('Expanding {} by max cost...'.format(all_terminals(node)))

        return self._expand_node_by_cost(node, max)

    def _log_tree(self, tree: DerivationTree) -> None:
        if self.log:
            print('Tree:', all_terminals(tree))
    
    def _expand_tree_with_strategy(self, tree: DerivationTree,
                                  expand_node_method: Callable,
                                  limit: Optional[int] = None):
        self.expand_node = expand_node_method
        while ((limit is None 
                or self._possible_expansions(tree) < limit) 
                and self._any_possible_expansions(tree)):
            tree = self._expand_tree_once(tree)
            self._log_tree(tree)
        return tree

    def expand_tree(self, tree: DerivationTree) -> DerivationTree:
        self._log_tree(tree)
        tree = self._expand_tree_with_strategy(tree, self._expand_node_max_cost, self.min_nonterminals)
        tree = self._expand_tree_with_strategy(tree, self._expand_node_randomly, self.max_nonterminals)
        tree = self._expand_tree_with_strategy(tree, self._expand_node_min_cost)

        assert self._possible_expansions(tree) == 0

        return tree

    def expansion_coverage(self) -> Set[str]:
        return self.covered_expansions

    def add_coverage(self, symbol: str,
                     new_child: Union[Expansion, List[DerivationTree]]) -> None:
        key = expansion_key(symbol, new_child)

        if self.log and key not in self.covered_expansions:
            print('New covered:', key)
        self.covered_expansions.add(key)

    def _max_expansion_coverage(self, symbol: str, max_depth: Union[int, float]) -> Set[str]:
        if max_depth <= 0:
            return set()

        self._symbols_seen.add(symbol)

        expansions = set()
        for expansion in self.grammar[symbol]:
            expansions.add(expansion_key(symbol, expansion))
            for nonterminal in nonterminals(expansion):
                if nonterminal not in self._symbols_seen:
                    expansions |= self._max_expansion_coverage(nonterminal, max_depth - 1)

        return expansions

    def max_expansion_coverage(self, symbol: Optional[str] = None,
                               max_depth: Union[int, float] = float('inf')) -> Set[str]:
        if symbol is None:
            symbol = self.start_symbol

        self._symbols_seen: Set[str] = set()
        cov = self._max_expansion_coverage(symbol, max_depth)

        if symbol == START_SYMBOL:
            assert len(self._symbols_seen) == len(self.grammar)

        return cov

    def _new_child_coverage(self,
                            children: List[DerivationTree],
                            max_depth: Union[int, float]) -> Set[str]:
        new_cov: Set[str] = set()

        for (c_symbol, _) in children:
            if c_symbol in self.grammar:
                new_cov |= self.max_expansion_coverage(c_symbol, max_depth)

        return new_cov

    def new_child_coverage(self, 
                           symbol: str,
                           children: List[DerivationTree],
                           max_depth: Union[int, float] = float('inf')) -> Set[str]:
        new_cov = self._new_child_coverage(children, max_depth)
        new_cov.add(expansion_key(symbol, children))
        new_cov = new_cov - self.expansion_coverage()
        return new_cov

    def new_coverages(self,
                      node: DerivationTree,
                      children_alternatives: List[List[DerivationTree]]) -> Optional[List[Set[str]]]:
        (symbol, children) = node
        for max_depth in range(len(self.grammar)):
            new_coverages = [self.new_child_coverage(symbol, c, max_depth)
                             for c in children_alternatives]
            max_new_coverage = max(len(new_coverage) for new_coverage in new_coverages)
            if max_new_coverage > 0:
                return new_coverages

        return None

    def fuzz_tree(self) -> DerivationTree:
        tree = self._init_tree()

        tree = self.expand_tree(tree)
        if self.log:
            print(repr(all_terminals(tree)))

        return tree

    def fuzz(self) -> str:
        self.derivation_tree = self.fuzz_tree()
        return all_terminals(self.derivation_tree)
