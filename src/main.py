from ethfuzzer import EthFuzzer

# from test import testc_contract_name, testc_solidity_version, testc_source_code
from test import erc_contract_name, erc_solidity_version, erc_source_code

ethFuzzer = EthFuzzer()

try:
    # create and deploy test contract
    # ethFuzzer.create_testc(testc_source_code, testc_contract_name, testc_solidity_version)
    ethFuzzer.create_testc(erc_source_code, erc_contract_name, erc_solidity_version)
    print('[*] test contract deployed at:', ethFuzzer.testc_address)
        
    for trail in range(0, 100):
        print(' - trail #' + str(trail) + ':', end=' ')
        
        # create atk contract and initialize variable
        (variables, source_code_without_parameters) = ethFuzzer.create_atkc_via_gfuzz()
        ethFuzzer.init_mfuzzer(variables)

        # deploy atk contract and execute it by atkc_deployer
        for step in range(0, 30):
            (coverage, testc_trace, atkc_source_code, tx_hash) = ethFuzzer.run(source_code_without_parameters)
            if step == 0 and coverage == set():
                # if first run is reverted, then discard this atk contract
                break

            # Detects if there is a violation during execution
            if coverage != set():
                ethFuzzer.oracle_detect(testc_trace, atkc_source_code, tx_hash)

            print('.', end='', flush=True)
        print('')

        # calculate overall coverage(cumulative_coverage)
        cumulative_coverage = ethFuzzer.get_cumulative_coverage()
        ethFuzzer.testc_coverage |= cumulative_coverage
        print(' - trail #' + str(trail) + ' coverage:', len(cumulative_coverage) / ethFuzzer.testc_opcode_number)
        print('[*] testc_coverage so far:', len(ethFuzzer.testc_coverage) / ethFuzzer.testc_opcode_number)

    print('[*] testc_coverage:', len(ethFuzzer.testc_coverage) / ethFuzzer.testc_opcode_number)
    
    # Summary
    (insecureArithmeticBreach) = ethFuzzer.result()
    print('[*] found {} breaches in InsecureArithmeticOracle'.format(len(insecureArithmeticBreach)))

    print('[*] output report')
    ethFuzzer.output_report()
except Exception as e:
    print('EthFuzzer Exception:', e)
finally:
    ethFuzzer.output_report()
    ethFuzzer.end()