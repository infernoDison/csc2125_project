import json
import os
import web3
import ens as ens_module
from web3.middleware import geth_poa_middleware

from eth_utils import keccak
import rlp
from rlp.sedes import (
    Binary,
    big_endian_int,
)
from trie import HexaryTrie
from web3._utils.encoding import pad_bytes


contract_addrs_file = "contract_addrs.json"
registry_name = "ENSRegistry"
registrar_name = "FIFSRegistrar"
tld = "eth"
record_offset = {'owner': 0, 'resolver': 1, 'ttl': 1, 'public_key': 2, 'ipv4_addr': 3, 'ipv6_addr': 4}


def connect_to_node():
    w3 = web3.Web3(web3.Web3.IPCProvider('./data/geth.ipc'))
    assert w3.isConnected(), "Failed to connect. Is geth running?"

    # Needed for geth PoA (dev mode)
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = w3.eth.accounts[0]

    return w3


def deploy_ens_fifs(w3):
    # Deploy registry, deploy registrar, attach registrar to eth TLD
    registry = deploy_contract(w3, registry_name)
    registrar = deploy_contract(w3, registrar_name, registry.address, w3.ens.namehash(tld))

    # Change eth TLD owner from contract creator to registrar
    wait_tx(w3, registry.functions.setSubnodeOwner(b'\0', w3.keccak(text=tld), registrar.address))

    return registry, registrar


def wait_tx(w3, tx):
    return w3.eth.waitForTransactionReceipt(tx.transact())


def deploy_contract(w3, name, *args):
    with open(f"./build/{name}.abi", "r") as f:
        abi = json.load(f)
    with open(f"./build/{name}.bin", "r") as f:
        bytecode = f.read()

    code = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_receipt = wait_tx(w3, code.constructor(*args))
    addr = tx_receipt.contractAddress
    contract = w3.eth.contract(address=addr, abi=abi)

    write_contract_addrs(name, addr)

    return contract


def load_contract(w3, name):
    with open(f"./build/{name}.abi", "r") as f:
        abi = json.load(f)
    with open("contract_addrs.json", "r") as f:
        addr = json.load(f)[name]

    contract = w3.eth.contract(address=addr, abi=abi)
    return contract


def write_contract_addrs(name, addr):
    addrs = {}
    if (os.path.exists(contract_addrs_file)):
        with open(contract_addrs_file, "r") as f:
            addrs = json.load(f)

    with open(contract_addrs_file, "w+") as f:
        addrs[name] = addr
        json.dump(addrs, f)


def storage_key(w3, name, field):
    namehash = w3.ens.namehash(name)
    # 0 is the slot of the "record" field in ENSRegistry.sol
    record_key = w3.toInt(w3.solidityKeccak(['uint256','uint256'], [w3.toInt(namehash), 0]))

    return record_key + record_offset[field]


def get_storage_proof(w3, registry, name, field):
    key = storage_key(w3, name, field)
    block_num = w3.eth.get_block('latest')['number']

    proof = w3.eth.get_proof(registry.address, [key], block_num)

    return proof, block_num


# Hash tree verification from web3py documentation
def format_proof_nodes(proof):
    trie_proof = []
    for rlp_node in proof:
        trie_proof.append(rlp.decode(bytes(rlp_node)))
    return trie_proof


def verify_eth_get_proof(proof, root):
    trie_root = Binary.fixed_length(32, allow_empty=True)
    hash32 = Binary.fixed_length(32)

    class _Account(rlp.Serializable):
        fields = [
                    ('nonce', big_endian_int),
                    ('balance', big_endian_int),
                    ('storage', trie_root),
                    ('code_hash', hash32)
                ]
    acc = _Account(
        proof.nonce, proof.balance, proof.storageHash, proof.codeHash
    )
    rlp_account = rlp.encode(acc)
    trie_key = keccak(bytes.fromhex(proof.address[2:]))

    assert rlp_account == HexaryTrie.get_from_proof(
        root, trie_key, format_proof_nodes(proof.accountProof)
    ), "Failed to verify account proof {}".format(proof.address)

    for storage_proof in proof.storageProof:
        trie_key = keccak(web3._utils.encoding.pad_bytes(b'\x00', 32, storage_proof.key))
        root = proof.storageHash
        if storage_proof.value == b'\x00':
            rlp_value = b''
        else:
            rlp_value = rlp.encode(storage_proof.value)

        assert rlp_value == HexaryTrie.get_from_proof(
            root, trie_key, format_proof_nodes(storage_proof.proof)
        ), "Failed to verify storage proof {}".format(storage_proof.key)

