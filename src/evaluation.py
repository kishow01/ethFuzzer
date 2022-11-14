if __name__ == '__main__':
    from ethfuzzer import EthFuzzer
    from dataset import SB_Curated_dataset

    for test_contract in SB_Curated_dataset:
        contract_name = test_contract['contract_name']
        bytecode = test_contract['bytecode']
        abi = test_contract['abi']
        
        ethFuzzer = EthFuzzer(gfuzz_iteration = 30, mfuzz_iteration = 30, divide_by_zero_detection_disable = True)
        (insecureArithmeticVulnerabilities, reentrancyVulnerabilities) = ethFuzzer.start('', '', '', bytecode, abi)

        a: bool = bool(insecureArithmeticVulnerabilities)
        r: bool = bool(reentrancyVulnerabilities)

        with open('../result.txt', 'a') as f:
            f.write('[-] fuzzing {}\n'.format(test_contract['contract_name']))
            f.write('[-] a: {}, r: {}\n'.format(a, r))
            if a == test_contract['label']['A'] and r == test_contract['label']['R']:
                f.write('[-] result: correct\n')
            else:
                f.write('[-] result: error\n')
            f.write('===========================\n')
    