
if __name__ == '__main__':
    from ethfuzzer import EthFuzzer

    testc_address = '0x819d03ccA9E15061E79EC3eaD32b190C18b23f84'
    testc_abi = [{'inputs': [], 'stateMutability': 'nonpayable', 'type': 'constructor'}, {'inputs': [], 'name': 'decrease', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [], 'name': 'increase', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [], 'name': 'number', 'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'stateMutability': 'view', 'type': 'function'}]
    
    ethFuzzer = EthFuzzer(gfuzz_iteration = 10, mfuzz_iteration = 10)
    ethFuzzer.run(testc_address, testc_abi, '', '')