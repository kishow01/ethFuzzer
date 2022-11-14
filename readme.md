# EthFuzzer
EthFuzzer is a fuzzing tool for Ethereum's smart contract. unlike other smart contract fuzzing tools that use the EOA Account as the starting point to perform fuzzing test on the target contract, EthFuzzer uses the Contract Account as the starting point to perform fuzzing test on the target contract. This means that EthFuzzer generates a variety of contracts, interacts the generated contracts with the target contract, and observes whether there is a breach of security between the transactions.

## prerequisite
1. ``ganache-cli``

## How to Use
### step 1. Start ganache private chain
Open a new console for ganache-cli
```
cd ethFuzzer/blockchain
ganache-cli --account_keys_path keys.json --port 8545 --defaultBalanceEther 1000000
```

the ganache-cli command would start a ganache blockchain server for testing, dont close this console during fuzzing.

### step 2. Deploy testing target in blockchain
there are some helper scripts in ethFuzzer/script directory.
+ you can put your contract source code, compiler version and contract name in ``contract_source_code.py``, and use ``python3 compile_and_deploy.py`` to compile and deploy your testing contract in blockchain, furthermore, you will get contract address and abi in script's output, this is input imformation for ethFuzzer.
+ you can put you bytecode and abi in ``contract_bytecode.py``, and use ``python3 deploy.py`` to deploy your testing contract in blockchain, also, you will get contract address and abi in script's output as well.

### step 3. Start fuzzing
```
cd ethFuzzer/src
python3 main.py
```

the ``main.py`` script need testing contract address and abi for fuzzing.

## Proof of Concept Testing
```
cd ethFuzzer/src
python3 test.py
```

## Evalutaion with dataset
```
cd ethFuzzer/src
python3 evaluation.py
```