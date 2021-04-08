from deploy_util import *
import accumulator

class LocalAcc:
    """
    Accumulator example pushing to a local smart contract.
    Assumes no one else is writing to the contract and
    errors out if any change is rejected.
    """

    def __init__(self, contract_name="AccVerifier"):
        self.w3 = connect_to_node()
        self.acc = accumulator.Accumulator()
        self.ver = deploy_contract(self.w3, contract_name)
        self.owner = self.w3.eth.accounts[0][2:] # Remove 0x prefix


    def _check_state(self):
        assert (self.acc._hash_tree[1].entry_hash == \
                self.ver.functions.rootHash().call().hex()), \
               "Root hash is inconsistent"
        assert (len(self.acc._entries) == self.ver.functions.numEntries().call()), \
               "Number of entries is inconsistent"


    def modify_entry(self, name_hash, public_key):
        entries, proofs = self.acc.acc_modify_entry(name_hash, public_key)
        wait_tx(self.w3, self.ver.functions.modifyEntry(*entries, *proofs, public_key))
        self._check_state()


    def add_entry(self, name_hash, public_key):
        entries, proofs = self.acc.acc_add_entry(name_hash, public_key, self.owner)
        wait_tx(self.w3, self.ver.functions.addEntry(*entries, *proofs, name_hash, public_key))
        self._check_state()


    def delete_entry(self, name_hash):
        entries, proofs = self.acc.acc_delete_entry(name_hash)
        wait_tx(self.w3, self.ver.functions.deleteEntry(*entries, *proofs))
        self._check_state()

