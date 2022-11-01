import random
import string
from typing import List, Callable

class DeletionMutator:
    def mutate(self, input: str) -> str:
        if input == '':
            return input
        
        position = random.randint(0, len(input) - 1)
        return input[0: position] + input[position + 1:]

class InsertionMutator:
    def mutate(self, input: str) -> str:
        position = random.randint(0, len(input))
        random_character = chr(random.randrange(32, 127))
        return input[0: position] + random_character + input[position:]

class FlipMutator:
    def mutate(self, input: str) -> str:
        if input == '':
            return input
        
        position = random.randint(0, len(input) - 1)
        char = input[position]
        bit = 1 << random.randint(0, 6)
        new_char = chr(ord(char) ^ bit)
        return input[0: position] + new_char + input[position + 1:]

class IntMutator:
    def __init__(self, type: str) -> None:
        self.type = type

    def mutate(self, input: int) -> int:
        if 'uint' in self.type:
            return random.randrange(0, pow(2, int(self.type.replace('uint', ''))))
        elif 'int' in self.type:
            return random.randrange(-1 * pow(2, int(self.type.replace('uint', '') - 1)), pow(2, int(self.type.replace('uint', '') - 1)))
        else:
            return 0
        

class AddressMutator:
    def __init__(self, checksum_address_list: List[str], to_checksum_function: Callable) -> None:
        self.checksum_address_list = checksum_address_list
        self.to_checksum_function = to_checksum_function
    
    def mutate(self, input: str) -> str:
        # mutate a valid address to invalid address or other address
        # invalid probability is  0.2
        if random.randrange(0, 10) <= 2:
            # generate invalid address by changing an valid address random char
            invalid_address = random.choice(self.checksum_address_list)

            position = random.randint(2, len(invalid_address) - 1)
            new_char = random.choice(string.hexdigits)

            invalid_address = invalid_address[0: position] + new_char + invalid_address[position + 1:]
            return self.to_checksum_function(invalid_address)
        else:
            return random.choice(self.checksum_address_list)
