testc_contract_name = 'Bank'
testc_solidity_version = '0.8.10'
testc_source_code = """
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
        balances[msg.sender] -= amount;   
        msg.sender.call{value: amount}("");
    }
}
"""

erc_contract_name = 'LcdToken'
erc_solidity_version = '0.6.0'
erc_source_code = """
pragma solidity 0.6.0;

contract LcdToken {
    string public name = 'Lcd Token';
    string public symbol = 'lcd';
    string public standard = 'Lcd Token v1.0';
    uint256 public totalSupply;
    
    event Transfer(
        address indexed _to,
        address indexed _from,
        uint256 _value
    );
    
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
    );
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    constructor() public {
        uint _initialSupply = 10000000;
        balanceOf[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        
        emit Transfer(_to, msg.sender, _value);
        
        return true;
    }
    
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] += _value;
        
        emit Approval(msg.sender ,_spender, _value);
        
        return true;
    }
    
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= balanceOf[_from]);
        require(_value <= allowance[_from][msg.sender]);
        
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        
        allowance[_from][msg.sender] -= _value;
        
        emit Transfer(_from, _to, _value);
        
        return true;
    }   
}
"""


overflow_contract_name = 'Overflow'
overflow_solidity_version = '0.8.0'
overflow_source_code = """
pragma solidity 0.8.0;

contract Overflow {
    uint256 public num;
    
    constructor() public {
        num = 0;
    }
    
    function add() public {
        num += 1;
    }
    
    function sub() public {
        num -= 1;
    }
}
"""