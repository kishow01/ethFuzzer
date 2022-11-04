from cgi import test

testing_contracts = [
    {
        'contract_name': 'IntegerOverflowMul',
        'compiler_version': '0.6.0',
        'source_code': 'pragma solidity 0.6.0; contract IntegerOverflowMul { uint public count = 2; function run(uint256 input1, uint256 input2) public { count = input1 * input2; }}',
        'label': {
            'R': False,
            'A': True
        }
    },
    {
        'contract_name': 'IntegerOverflowMulFixed',
        'compiler_version': '0.8.10',
        'source_code': 'pragma solidity 0.8.10; contract IntegerOverflowMulFixed { uint public count = 2; function run(uint256 input1, uint256 input2) public { count = input1 * input2; }}',
        'label': {
            'R': False,
            'A': False
        }
    },
    {
        'contract_name': 'Bank',
        'compiler_version': '0.8.10',
        'source_code': 'pragma solidity 0.8.10; contract Bank { address owner; mapping(address => uint256) public balances; constructor() public { owner = msg.sender; } function deposite() public payable { balances[msg.sender] += msg.value; } function withdraw(uint256 amount) public { require(balances[msg.sender] >= amount); msg.sender.call{value: amount}(""); balances[msg.sender] -= amount; } }',
        'label': {
            'R': True,
            'A': False
        }
    },
    {
        'contract_name': 'BankFixed',
        'compiler_version': '0.8.10',
        'source_code': 'pragma solidity 0.8.10; contract BankFixed { address owner; mapping(address => uint256) public balances; constructor() public { owner = msg.sender; } function deposite() public payable { balances[msg.sender] += msg.value; } function withdraw(uint256 amount) public { require(balances[msg.sender] >= amount); balances[msg.sender] -= amount; msg.sender.call{value: amount}(""); } }',
        'label': {
            'R': False,
            'A': False
        }
    }
]

if __name__ == '__main__':
    from ethfuzzer import EthFuzzer

    for test_contract in testing_contracts:
        source_code = test_contract['source_code']
        contract_name = test_contract['contract_name']
        solidity_version = test_contract['compiler_version']

        ethFuzzer = EthFuzzer(gfuzz_iteration = 10, mfuzz_iteration = 10, divide_by_zero_detection_disable = True)
        (insecureArithmeticBreach, reentrancyBreach) = ethFuzzer.run(source_code, contract_name, solidity_version, report_enable = False)

        a: bool = bool(insecureArithmeticBreach)
        r: bool = bool(reentrancyBreach)

        with open('../result.txt', 'a') as f:
            f.write('[-] fuzzing {}\n'.format(test_contract['contract_name']))
            f.write('[-] a: {}, r: {}\n'.format(a, r))
            if a == test_contract['label']['A'] and r == test_contract['label']['R']:
                f.write('[-] result: correct\n')
            else:
                f.write('[-] result: error\n')
            f.write('===========================\n')