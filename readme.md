# EthFuzzer
EthFuzzer is a fuzzing tool for Ethereum's smart contract. unlike other smart contract fuzzing tools that use the EOA Account as the starting point to perform fuzzing test on the target contract, EthFuzzer uses the Contract Account as the starting point to perform fuzzing test on the target contract. This means that EthFuzzer generates a variety of contracts, interacts the generated contracts with the target contract, and observes whether there is a breach of security between the transactions.

