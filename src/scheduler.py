import pickle
import hashlib
import random
from typing import Sequence, Set, List, Dict, Union, Any

class Variable:
    def __init__(self, 
                 label: str, 
                 type: str, 
                 data: str = None) -> None:
        self.label = label
        self.type = type
        self.data = data

class Seed:
    def __init__(self, 
                 vairalbe_list: List[Variable]) -> None:
        self.variable_list = vairalbe_list

        # coverage format 'pc'+'_'+'opcode'
        self.coverage: Set[str] = set()
        self.energy = 0.0

class Scheduler:
    def __init__(self, exponent: float) -> None:
        self.path_frequency: Dict = {}
        self.exponent = exponent

    def getPathID(self, coverage: Any) -> str:
        pickled = pickle.dumps(coverage)
        return hashlib.md5(pickled).hexdigest()

    def assignEnergy(self, population: Sequence[Seed]) -> None:
        for seed in population:
            seed.energy = 1 / (self.path_frequency[self.getPathID(seed.coverage)] ** self.exponent)

    def normalizedEnergy(self, population: Sequence[Seed]) -> List[float]:
        energy = list(map(lambda seed: seed.energy, population))
        sum_energy = sum(energy)
        assert sum_energy != 0
        norm_energy = list(map(lambda e: e / sum_energy, energy))
        return norm_energy

    def update_path_frequency(self, path_id: str) -> None:
        if path_id not in self.path_frequency:
            self.path_frequency[path_id] = 1
        else:
            self.path_frequency[path_id] += 1

    def choose(self, population: Sequence[Seed]) -> Seed:
        self.assignEnergy(population)
        norm_energy = self.normalizedEnergy(population)
        seed: Seed = random.choices(population, weights = norm_energy)[0]
        return seed		