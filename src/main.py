
if __name__ == '__main__':
    from ethfuzzer import EthFuzzer

    contract_name = 'Bank'
    solidity_version = '0.8.10'
    source_code = """
    pragma solidity 0.8.10;
    contract Bank {
	    address owner;
        mapping(address => uint256) public balances;

        constructor() public {
            owner = msg.sender;
        }

	    function deposite() public payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    ethFuzzer = EthFuzzer(gfuzz_iteration = 10, mfuzz_iteration = 10)
    ethFuzzer.run(source_code, contract_name, solidity_version)