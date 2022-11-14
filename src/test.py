if __name__ == '__main__':
    from ethfuzzer import EthFuzzer
    from dataset import POC_dataset

    for test_contract in POC_dataset:
        source_code = test_contract['source_code']
        contract_name = test_contract['contract_name']
        solidity_version = test_contract['compiler_version']

        ethFuzzer = EthFuzzer(gfuzz_iteration = 10, mfuzz_iteration = 10, divide_by_zero_detection_disable = True)
        (insecureArithmeticVulnerabilities, reentrancyVulnerabilities) = ethFuzzer.start(source_code, contract_name, solidity_version)

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