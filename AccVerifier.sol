// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.2 <0.9.0;

/**
 * @title AccVerifier
 * @dev Stores and persists changes to an off-chain accumulator
 */
contract AccVerifier {

    struct NameEntry {
        bytes32 nameHash;
        bytes32 nextHash;
        bytes32 publicKey;
        address owner;
        uint256 treeIndex;
    }


    bytes32 public rootHash;
    uint256 public numEntries;


    constructor() {
        rootHash = calcEntryHash(NameEntry(
            0x0, bytes32(type(uint256).max), 0x0, address(0x0), 1
        ));
        numEntries = 1;
    }


    function calcEntryHash(
        NameEntry memory entry
    )
    public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            entry.nameHash, entry.nextHash, entry.publicKey, entry.owner, entry.treeIndex
        ));
    }


    function calcRootHash(
        bytes32 entryHash,
        bytes32[] memory proof,
        uint256 entryIndex
    )
    public pure returns (bytes32) {
        for (uint256 i = 0; i < proof.length; i++) {
            if ((entryIndex & 1) == 0) { // Entry is left element
                entryHash = keccak256(abi.encodePacked(entryHash, proof[i]));
            }
            else {
                entryHash = keccak256(abi.encodePacked(proof[i], entryHash));
            }

            entryIndex >>= 1;
        }

        return entryHash;
    }


    function modifyEntry(
        NameEntry memory entry,
        bytes32[] calldata proof,
        bytes32 publicKey
    )
    public {
        bytes32 hash;

        // Validate entry
        require (entry.owner == msg.sender,
                 "Requester does not own this entry");

        // Verify proof and update root
        hash = calcRootHash(calcEntryHash(entry), proof, entry.treeIndex);
        require (hash == rootHash, "Membership proof is invalid");
        entry.publicKey = publicKey;
        rootHash = calcRootHash(calcEntryHash(entry), proof, entry.treeIndex);
    }


    function addEntry(
        NameEntry memory splitEntry,
        NameEntry memory siblingEntry,
        bytes32[] calldata splitProof,
        bytes32[] calldata siblingProof,
        bytes32 nameHash,
        bytes32 publicKey
    )
    public {
        bytes32 hash;
        NameEntry memory newEntry;

        // Validate entries
        require (splitEntry.nameHash < nameHash && splitEntry.nextHash > nameHash,
                 "New name hash is not in range");
        // New sibling is the parent of the to-be-appended entry
        require (siblingEntry.treeIndex == numEntries,
                 "New sibling is not the first leaf");

        newEntry = NameEntry(nameHash, splitEntry.nextHash, publicKey, msg.sender, (numEntries*2+1));

        // Verify proofs and update root
        // Operation 1: Update old entry to be lower half of interval
        hash = calcRootHash(calcEntryHash(splitEntry), splitProof, splitEntry.treeIndex);
        require (hash == rootHash, "Non-membership proof is invalid");
        splitEntry.nextHash = nameHash;
        rootHash = calcRootHash(calcEntryHash(splitEntry), splitProof, splitEntry.treeIndex);

        // Operation 2: Append new entry containing upper half of interval
        hash = calcRootHash(calcEntryHash(siblingEntry), siblingProof, siblingEntry.treeIndex);
        require (hash == rootHash, "Sibling entry proof is invalid");
        siblingEntry.treeIndex = numEntries*2;
        rootHash = calcRootHash(
            keccak256(abi.encodePacked(calcEntryHash(siblingEntry), calcEntryHash(newEntry))),
            siblingProof, numEntries
        );

        numEntries++;
    }


    function deleteEntry(
        NameEntry memory mergeEntry,
        NameEntry memory delEntry,
        NameEntry memory lastEntry,
        NameEntry memory lastEntrySibling,
        bytes32[] calldata mergeProof,
        bytes32[] calldata delProof,
        bytes32[] calldata lastProof
    )
    public {
        bytes32 hash;
        bytes32 lastEntryHash;
        uint256 lastEntryIndex;

        // Validate entries
        require (delEntry.owner == msg.sender,
                 "Requester does not own this entry");
        require (mergeEntry.nextHash == delEntry.nameHash,
                 "Merge entry is not adjacent");
        require (lastEntry.treeIndex == (numEntries*2-1),
                 "Last entry is not the last in the tree");
        require (lastEntrySibling.treeIndex == (numEntries*2-2),
                 "Last entry sibling is not the second last in the tree");

        lastEntryHash = calcEntryHash(lastEntry);
        lastEntryIndex = lastEntry.treeIndex;

        // Verify proofs and update root
        // Operation 1: Update preceding entry to be entire interval
        hash = calcRootHash(calcEntryHash(mergeEntry), mergeProof, mergeEntry.treeIndex);
        require(hash == rootHash, "Merge entry proof is invalid");
        mergeEntry.nextHash = delEntry.nextHash;
        rootHash = calcRootHash(calcEntryHash(mergeEntry), mergeProof, mergeEntry.treeIndex);

        // Operation 2: Move last entry into tree location of current entry
        hash = calcRootHash(calcEntryHash(delEntry), delProof, delEntry.treeIndex);
        require(hash == rootHash, "Membership proof is invalid");
        lastEntry.treeIndex = delEntry.treeIndex;
        rootHash = calcRootHash(calcEntryHash(lastEntry), delProof, lastEntry.treeIndex);

        // Operation 3: Delete last entry
        hash = calcRootHash(
            keccak256(abi.encodePacked(calcEntryHash(lastEntrySibling), lastEntryHash)), 
            lastProof, numEntries-1
        );
        require(hash == rootHash, "Last entry proof is invalid");
        lastEntrySibling.treeIndex = numEntries-1;
        rootHash = calcRootHash(calcEntryHash(lastEntrySibling), lastProof, lastEntrySibling.treeIndex);

        numEntries--;
    }
}
