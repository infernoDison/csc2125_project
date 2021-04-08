import copy
from eth_utils import (
    keccak,
    remove_0x_prefix,
)
from web3._utils.encoding import hex_encode_abi_type


class HashTreeEntry:
    def __init__(self, entry_hash='00'*32):
        self.entry_hash = entry_hash


class NameEntry(HashTreeEntry):
    def __init__(self, name_hash, next_hash, public_key, owner, tree_index):
        self.name_hash = name_hash      # bytes32 (hex string)
        self.next_hash = next_hash      # bytes32 (hex string)
        self.public_key = public_key    # bytes32 (hex string)
        self.owner = owner              # address (20 byte hex string)
        self.tree_index = tree_index    # uint256

        self.update_entry_hash()


    def update_entry_hash(self):
        self.entry_hash = keccak(hexstr=(
            self.name_hash + self.next_hash + self.public_key + self.owner + \
            remove_0x_prefix(hex_encode_abi_type("uint256", self.tree_index))
        )).hex()


    def get_formatted_tuple(self):
        return (
            self.name_hash,
            self.next_hash,
            self.public_key,
            '0x' + self.owner,
            self.tree_index
        )




class Accumulator:
    ### Internal functions
    def __init__(self):
        # List of name entries sorted by name hash
        self._entries = [NameEntry('00'*32, 'ff'*32, '00'*32, '00'*20, 1)]
        self._hash_tree = [HashTreeEntry(), self._entries[0]]

    
    # Hash tree manipulation
    def _tree_update_hashes(self, parent_index):
        while (parent_index >= 1):
            self._hash_tree[parent_index].entry_hash = keccak(hexstr=(
                self._hash_tree[parent_index*2].entry_hash + 
                self._hash_tree[parent_index*2+1].entry_hash
            )).hex()
            parent_index //= 2


    def _tree_update(self, entry):
        entry.update_entry_hash()
        self._tree_update_hashes(entry.tree_index//2)

    
    def _tree_append(self, entry):
        # Move parent of latest position to latest (left child) and append new (right child)
        last_index = len(self._hash_tree)
        parent = self._hash_tree[last_index//2]
        parent.tree_index = last_index
        parent.update_entry_hash()
        self._hash_tree.append(parent)
        self._hash_tree.append(entry)
        self._hash_tree[last_index//2] = HashTreeEntry()
        self._tree_update_hashes(last_index//2)


    def _tree_delete_last(self):
        assert (len(self._hash_tree) > 2), "Can not delete from empty hash tree"
        # Delete from latest (right child) and move left child up a level
        parent_index = (len(self._hash_tree)-1)//2
        self._hash_tree.pop()
        sibling = self._hash_tree.pop()
        sibling.tree_index = parent_index
        sibling.update_entry_hash()
        self._hash_tree[parent_index] = sibling
        self._tree_update_hashes(parent_index//2)
        



    ### Externally callable functions
    def tree_get_proof(self, tree_index):
        """
        Get the Merkle proof associated with an tree index.
        The index is enough to determine whether the siblings in the proof
        are on the left or right.
        """

        proof = []
        while (tree_index > 1):
            sibling_index = tree_index + (1 if (tree_index % 2 == 0) else -1)
            proof.append(self._hash_tree[sibling_index].entry_hash)
            tree_index //= 2

        return proof


    def acc_find_entry(self, name_hash):
        """
        Find the entry corresponding to the name hash if it is registered, 
        and the one corresponding to the interval containing it
        if it is not registered.
        """
        # Linear search; can be made binary if needed
        for i in reversed(range(len(self._entries))):
            if (name_hash >= self._entries[i].name_hash):
                return (self._entries[i], i)

        assert False, "No interval containing the name hash was found \
                       (this should never happen)"


    def acc_modify_entry(self, name_hash, public_key):
        """
        Change the public key associated with an entry.
        """

        entry, entry_index = self.acc_find_entry(name_hash)

        assert (name_hash == entry.name_hash), \
               f"No entry found for name hash {name_hash}"

        entries = []
        proofs = []

        # Membership proof for entry
        entries.append(entry.get_formatted_tuple())
        proofs.append(self.tree_get_proof(entry.tree_index))
        entry.public_key = public_key
        self._tree_update(entry)

        return entries, proofs


    def acc_add_entry(self, name_hash, public_key, owner):
        """
        Add a new entry to the accumulator.
        The sending account is recorded as the owner in the smart contract.
        """

        split_entry, split_index = self.acc_find_entry(name_hash)
        sibling_entry = self._hash_tree[len(self._hash_tree)//2]

        assert (name_hash != split_entry.name_hash), \
               f"Name hash {name_hash} is already registered"
        assert (name_hash > split_entry.name_hash and name_hash < split_entry.next_hash), \
               f"Non-membership entry for name hash {name_hash} is invalid"

        new_entry = NameEntry(name_hash, split_entry.next_hash, public_key,
                              owner, len(self._hash_tree)+1)

        entries = []
        proofs = []

        # Split interval in two
        # Operation 1: Update old entry to be lower half of interval
        # Non-membership proof for name hash
        entries.append(split_entry.get_formatted_tuple())
        proofs.append(self.tree_get_proof(split_entry.tree_index))
        split_entry.next_hash = name_hash
        self._tree_update(split_entry)

        # Operation 2: Append new entry containing upper half of interval
        # Membership proof for parent of to-be-appended entry
        entries.append(sibling_entry.get_formatted_tuple())
        proofs.append(self.tree_get_proof(sibling_entry.tree_index))
        self._entries.insert(split_index+1, new_entry)
        self._tree_append(new_entry)

        return entries, proofs


    def acc_delete_entry(self, name_hash):
        """
        Delete an entry from the accumulator.
        Only the owner recorded in the smart contract is allowed to do this.
        """

        entry, entry_index = self.acc_find_entry(name_hash)
        merge_entry = self._entries[entry_index-1]
        last_entry = self._hash_tree[-1]

        assert (name_hash == entry.name_hash), \
               f"No entry found for name hash {name_hash}"
        assert (entry_index != 0), "Can not delete placeholder entry"

        entries = []
        proofs = []

        # Merge intervals
        # Operation 1: Update preceding entry to be entire interval
        # Membership proof for preceding entry
        entries.append(merge_entry.get_formatted_tuple())
        proofs.append(self.tree_get_proof(merge_entry.tree_index))
        merge_entry.next_hash = entry.next_hash
        self._tree_update(merge_entry)

        # Operation 2: Move last entry into tree location of current entry
        # This does nothing if the current entry is the last entry
        # Membership proof for current entry
        entries.append(entry.get_formatted_tuple())
        proofs.append(self.tree_get_proof(entry.tree_index))
        # Move the reference since self._entries points to last_entry
        temp_last_entry = copy.copy(last_entry)
        last_entry.tree_index = entry.tree_index
        self._hash_tree[-1] = temp_last_entry
        self._hash_tree[entry.tree_index] = last_entry
        self._tree_update(last_entry)

        # Operation 3: Delete last entry
        # Membership proof for last entry and its sibling
        entries.append(self._hash_tree[-1].get_formatted_tuple())
        entries.append(self._hash_tree[-2].get_formatted_tuple())
        proofs.append(self.tree_get_proof(len(self._entries)-1))
        self._tree_delete_last()
        self._entries.pop(entry_index)

        return entries, proofs


    def print_state(self):
        print("Entries")
        for entry in self._entries:
            print(entry)
            print(entry.get_formatted_tuple())

        print("Hash tree")
        for i in range(len(self._hash_tree)):
            print("" + str(i) + "\t" + self._hash_tree[i].entry_hash + \
                  "\t" + str(self._hash_tree[i]))


def tree_calc_root(entry_hash, proof, tree_index):
    for sibling in proof:
        if (tree_index % 2 == 0):
            entry_hash = keccak(hexstr=(entry_hash + sibling)).hex()
        else:
            entry_hash = keccak(hexstr=(sibling + entry_hash)).hex()
        tree_index //= 2

    return entry_hash

