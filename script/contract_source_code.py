source_code = """
pragma solidity 0.6.10;

contract ExampleOverflow {
    uint public number;

    constructor() public {
        number = 0;
    }

    function increase() public {
        number++;
    }

    function decrease() public {
        number--;
    }
}

"""

compiler_version = '0.6.10'
contract_name = 'ExampleOverflow'