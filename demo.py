from demo_util import *

def register():
    w3 = connect_to_node()
    registry, registrar = deploy_ens_fifs(w3)

    name_hash = w3.ens.namehash("foo.eth")
    wait_tx(w3, registrar.functions.register(w3.keccak(text="foo"), w3.eth.default_account))
    wait_tx(w3, registry.functions.setPublicKey(name_hash, 12345))
    wait_tx(w3, registry.functions.setIpv4Address(name_hash, w3.toInt(0x7f000001)))

