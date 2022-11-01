from ethfuzzer import EthFuzzer

"""from test import testc_contract_name, testc_solidity_version, testc_source_code"""
from test import erc_contrace_name, erc_solidity_version, erc_source_code

ethFuzzer = EthFuzzer()

try:
    # create and deploy test contract
    """ethFuzzer.create_testc(testc_source_code, testc_contract_name, testc_solidity_version)"""
    ethFuzzer.create_testc(erc_source_code, erc_contrace_name, erc_solidity_version)
        
    for trail in range(0, 10):
        print(' - trail #' + str(trail) + ':', end=' ')
        
        # create atk contract and initialize variable
        (variables, source_code_without_parameters) = ethFuzzer.create_atkc_via_gfuzz()
        ethFuzzer.init_mfuzzer(variables)

        # deploy atk contract and execute it by atkc_deployer
        for step in range(0, 100):
            (evm_exception, atkc_source_code) = ethFuzzer.run(source_code_without_parameters)
            if evm_exception:
                break

            cumulative_coverage = ethFuzzer.get_cumulative_coverage()
            print('.', end='', flush=True)
        print('')

        # calculate overall coverage(cumulative_coverage)
        cumulative_coverage = ethFuzzer.get_cumulative_coverage()
        ethFuzzer.testc_coverage |= cumulative_coverage
        print(' - trail #' + str(trail) + ' coverage:', len(cumulative_coverage) / ethFuzzer.testc_opcode_number)
        print('[*] testc_coverage so far:', len(ethFuzzer.testc_coverage) / ethFuzzer.testc_opcode_number)

    print('[*]testc_coverage:', len(ethFuzzer.testc_coverage) / ethFuzzer.testc_opcode_number)
except Exception as e:
    print('EthFuzzer Exception:', e)
    print(e)
finally:
    ethFuzzer.end()