
if __name__ == '__main__':
    from ethfuzzer import EthFuzzer

    testc_address = ''
    testc_abi = ''
    
    ethFuzzer = EthFuzzer(gfuzz_iteration = 10, mfuzz_iteration = 10)
    ethFuzzer.run(testc_address, testc_abi)