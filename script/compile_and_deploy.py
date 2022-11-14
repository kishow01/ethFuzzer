import os
import json
from web3 import Web3, HTTPProvider
from solcx import compile_source, install_solc

from contract_source_code import source_code, contract_name, compiler_version

host = '127.0.0.1'
port = 8545
DEFAULT_BLOCKCHAIN_KEY_LOCATION = '../blockchain/keys.json'

w3 = Web3(HTTPProvider("http://{}:{}".format(host, port)))

print('connection status:', w3.isConnected())

if not os.path.exists(DEFAULT_BLOCKCHAIN_KEY_LOCATION):
    raise FileNotFoundError('No keys.json in blockchain directory')

with open(DEFAULT_BLOCKCHAIN_KEY_LOCATION) as file:
    accounts = json.load(file)

address_list = list(accounts['private_keys'].keys())
checksum_address_list = [w3.toChecksumAddress(address) for address in accounts['private_keys'].keys()]
privateKey_of_EOAs = [accounts['private_keys'][pubKey] for pubKey in address_list]

acct = w3.eth.account.privateKeyToAccount(privateKey_of_EOAs[0])

install_solc(compiler_version)

tmp = compile_source(source_code, output_values = ['abi', 'bin'], solc_version = compiler_version)
abi = tmp['<stdin>:' + contract_name]['abi']
bytecode = tmp['<stdin>:' + contract_name]['bin']

contract = w3.eth.contract(abi = abi, bytecode = bytecode)

tx = contract.constructor().buildTransaction({
	'from': acct.address,
	'nonce': w3.eth.get_transaction_count(acct.address)
})

tx_signed = w3.eth.account.sign_transaction(tx, acct.privateKey)

tx_hash = w3.eth.send_raw_transaction(tx_signed.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print('contract deployed at', tx_receipt.contractAddress)
print('abi:', abi)