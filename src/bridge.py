from web3 import Web3, HTTPProvider
from solcx import compile_source, install_solc
import requests
import json
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as RequestsConnectionError
from typing import Tuple, List

from exception import *
from util import *

# Install solidity compiler version 0.8.10
install_solc("0.8.10")

class Bridge:
    """
    This class handles the interaction between python program and blockchain.
    support web3.py interface and json-rpc.
    for deploy contract, contract interaction, ...etc, use web3.py
    for tracing transaction, use json-rpc 'debug_traceTransaction'
    """
    def __init__(self, 
                 host: str = '127.0.0.1', 
                 port: int = DEFAULT_BLOCKCHAIN_PORT):
        self.w3 = Web3(HTTPProvider("http://{}:{}".format(host, port)))
        self.host = host
        self.port = port
        self.session = requests.Session()
        self.session.mount(self.host, HTTPAdapter())

    def connectStatus(self):
        return self.w3.isConnected()

    ###############################################################
    #                           web3.py                           #
    ###############################################################
    def web3_compile_test_contract(self, 
                                   source_code: str,
                                   contract_name: str,
                                   compiler_version: str):
        assert compiler_version in SUPPORTED_COMPILER_VERSION, 'GIVEN COMPILER VERSION NOT SUPPORTTED'
        install_solc(compiler_version)

        tmp = compile_source(source_code, output_values = ['abi', 'bin'], solc_version = compiler_version)
        testc_abi = tmp['<stdin>:' + contract_name]['abi']
        testc_bytecode = tmp['<stdin>:' + contract_name]['bin']

        return (testc_abi, testc_bytecode)


    def web3_deploy_test_contract(self, 
                                  sender_privateKey: str,
                                  testc_abi, 
                                  testc_bytecode):
        contract = self.w3.eth.contract(abi = testc_abi, bytecode = testc_bytecode)
        testc_deployer_acct = self.w3.eth.account.privateKeyToAccount(sender_privateKey)

        constructor_abi = [abi for abi in testc_abi if abi['type'] == 'constructor']

        if len(constructor_abi) and constructor_abi[0]['stateMutability'] == 'payable':
            value = ether_to_wei(50)
        else:
            value = 0

        tx = contract.constructor().buildTransaction({
            'value': value,
            'from': testc_deployer_acct.address,
            'nonce': self.w3.eth.get_transaction_count(testc_deployer_acct.address)
        })

        tx_signed = self.w3.eth.account.sign_transaction(tx, testc_deployer_acct.privateKey)
        tx_hash = self.w3.eth.send_raw_transaction(tx_signed.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        self.testc_address = tx_receipt.contractAddress

        return tx_receipt.contractAddress
    
    def web3_direct_deploy_testc(self, testc_abi, testc_bytecode, sender_privateKey):
        contract = self.w3.eth.contract(abi = testc_abi, bytecode = testc_bytecode)
        testc_deployer_acct = self.w3.eth.account.privateKeyToAccount(sender_privateKey)

        constructor_abi = [abi for abi in testc_abi if abi['type'] == 'constructor']

        if len(constructor_abi) and constructor_abi[0]['stateMutability'] == 'payable':
            value = ether_to_wei(50)
        else:
            value = 0

        tx = contract.constructor().buildTransaction({
            'value': value,
            'from': testc_deployer_acct.address,
            'nonce': self.w3.eth.get_transaction_count(testc_deployer_acct.address)
        })

        tx_signed = self.w3.eth.account.sign_transaction(tx, testc_deployer_acct.privateKey)
        tx_hash = self.w3.eth.send_raw_transaction(tx_signed.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        self.testc_address = tx_receipt.contractAddress

        return (tx_receipt.contractAddress, testc_abi)

    def web3_deploy_attacker_contract(self, 
                                      sender_privatekey: str,
                                      source_code: str) -> Tuple[str, List]:
        """Compile and deploy given contract and return its contract address and abi"""

        temp_file = compile_source(source_code, output_values = ['abi', 'bin'], solc_version = '0.8.10')
        abi = temp_file['<stdin>:TestContract']['abi']
        bytecode = temp_file['<stdin>:TestContract']['bin']

        contract = self.w3.eth.contract(abi = abi, bytecode = bytecode)
        acct = self.w3.eth.account.privateKeyToAccount(sender_privatekey)

        tx = contract.constructor().buildTransaction({
            'from': acct.address,
            'nonce': self.w3.eth.get_transaction_count(acct.address)
        })

        tx_signed = self.w3.eth.account.sign_transaction(tx, acct.privateKey)
        tx_hash = self.w3.eth.send_raw_transaction(tx_signed.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return (tx_receipt.contractAddress, abi)
    
    def web3_call(self, 
                  contract_address: str, 
                  sender_privateKey: str,
                  value: int,
                  gasPrice: int = 2000000000, 
                  gas: int = 500000) -> str:
        sender_acct = self.w3.eth.account.privateKeyToAccount(sender_privateKey)

        tx = self.w3.eth.account.sign_transaction(
            {
                "nonce": self.w3.eth.get_transaction_count(sender_acct.address),
                "gasPrice": gasPrice,
                "gas": gas,
                "to": contract_address,
                "data": self.w3.sha3(text = "test()")[0:4].hex()
            },
            sender_acct.privateKey
        )

        tx_hash = self.w3.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return tx_hash.hex()

    def web3_getCode(self,
                     address: str) -> str:
        return self.w3.eth.getCode(address)

    ###############################################################
    #                              eth                            #
    ###############################################################
    
    def eth_blockNumber(self):
        return self.__call("eth_blockNumber")

    def eth_accounts(self):
        return self.__call("eth_accounts")

    def eth_coinbase(self):
        return self.__call("eth_coinbase")
    
    def eth_getBlockByHash(self, block_hash, tx_objects=True):
        return self.__call("eth_getBlockByHash", [block_hash, tx_objects])

    def eth_getBlockByNumber(self, block=BLOCK_TAG_LATEST, tx_objects=True):
        block = validate_block(block)
        return self.__call("eth_getBlockByNumber", [block, tx_objects])
    
    def eth_getTransactionByHash(self, tx_hash):
        return self.__call("eth_getTransactionByHash", [tx_hash])

    def eth_getTransactionByBlockHashAndIndex(self, block_hash, index=0):
        return self.__call("eth_getTransactionByBlockHashAndIndex", [block_hash, hex(index)])

    def eth_getTransactionByBlockNumberAndIndex(self, block=BLOCK_TAG_LATEST, index=0):
        block = validate_block(block)
        return self.__call("eth_getTransactionByBlockNumberAndIndex", [block, hex(index)])

    def eth_getTransactionReceipt(self, tx_hash):
        return self.__call("eth_getTransactionReceipt", [tx_hash])

    def eth_getCompilers(self):
        return self.__call("eth_getCompilers")

    def eth_compileSolidity(self, code):
        return self.__call("eth_compileSolidity", [code])

    def eth_sendTransaction(self, 
                            to_address=None, 
                            from_address=None, 
                            gas=None, 
                            gas_price=None, 
                            value=None, 
                            data=None,
                            nonce=None):
        params = {}
        params["from"] = from_address or self.eth_coinbase()

        if to_address is not None:
            params["to"] = to_address
        if gas is not None:
            params["gas"] = hex(gas)
        if gas_price is not None:
            params["gas_price"] = clean_hex(gas_price)
        if value is not None:
            params["value"] = clean_hex(value)
        if data is not None:
            params["data"] = data
        if nonce is not None:
            params["nonce"] = hex(nonce)

        return self.__call("eth_sendTransaction", [params])
        
    def eth_sendRawTransaction(self, data):
        return self.__call('eth_sendRawTransaction', [data])

    def eth_call(self, 
                 to_address, 
                 from_address=None, 
                 gas=None, 
                 gas_price=None, 
                 value=None, 
                 data=None,
                 default_block=BLOCK_TAG_LATEST):
        if isinstance(default_block, str):
            if default_block not in BLOCK_TAGS:
                raise ValueError
        obj = {}
        obj["to"] = to_address
        if from_address is not None:
            obj["from"] = from_address
        if gas is not None:
            obj["gas"] = hex(gas)
        if gas_price is not None:
            obj["gasPrice"] = clean_hex(gas_price)
        if value is not None:
            obj["value"] = value
        if data is not None:
            obj["data"] = data
        return self.__call("eth_call", [obj, default_block])

    def eth_getBalance(self, addr):
        return self.__call('eth_getBalance', [addr])

    ###############################################################
    #                              net                            #
    ###############################################################
    def net_listening(self):
        return self.__call("net_listening")

    def net_peerCount(self):
        return self.__call("net_peerCount")

    ###############################################################
    #                              debug                          #
    ###############################################################
    def debug_dumpBlock(self, num):
        return self.__call("debug_dumpBlock", [num])

    def debug_traceTransaction(self, txhash):
        return self.__call("debug_traceTransaction", [txhash, []])
    
    ###############################################################
    #                              other                          #
    ###############################################################
    def transfer(self,
                 from_: str,
                 to_: str,
                 amount: int):
        return self.eth_sendTransaction(from_address=from_, to_address=to_, value=amount)

    def get_contract_address(self, tx):
        receipt = self.eth_getTransactionReceipt(tx)
        return receipt["contractAddress"]

    ###############################################################
    #                           private                           #
    ###############################################################
    def __call(self, 
               method: str, 
               params: str = None, 
               _id=1):
        if params == None:
            params = []

        data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": _id
        }

        scheme = "http"
        url = "{}://{}:{}".format(scheme, self.host, self.port)
        headers = { "Content-Type": "application/json"}

        try:
            r = self.session.post(url, headers=headers, data=json.dumps(data))
        except RequestsConnectionError:
            raise ConnectionError

        if r.status_code / 100 != 2:
            raise BadStatusCodeError(r.status_code)

        try:
            response = r.json()
        except ValueError:
            raise BadJsonError(r.text)

        try:
            return response['result']
        except KeyError:
            raise BadResponseError(response)
