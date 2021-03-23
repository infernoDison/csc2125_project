import json
import web3
import ens as ens_module
from web3.middleware import geth_poa_middleware


contract_name = "ENSRegistry"


def connect_to_node():
    w3 = web3.Web3(web3.Web3.IPCProvider('./data/geth.ipc'))
    assert w3.isConnected(), "Failed to connect. Is geth running?"

    # Needed for geth PoA (dev mode)
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = w3.eth.accounts[0]

    return w3


def deploy_contract(w3):
    with open(f"./build/{contract_name}.abi", "r") as f:
        abi = json.load(f)
    with open(f"./build/{contract_name}.bin", "r") as f:
        bytecode = f.read()

    registry_code = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = registry_code.constructor().transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    contract_addr = tx_receipt.contractAddress
    registry = w3.eth.contract(address=contract_addr, abi=abi)

    with open("contract_addr.txt", "w") as f:
        f.write(contract_addr)

    return registry


def load_contract(w3):
    with open(f"./build/{contract_name}.abi", "r") as f:
        abi = json.load(f)
    with open("contract_addr.txt", "r") as f:
        contract_addr = f.read()

    registry = w3.eth.contract(address=contract_addr, abi=abi)
    return registry

