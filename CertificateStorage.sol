pragma solidity >=0.4.16 <0.9.0;

contract CertificateStorage {
    
    // mapping(string =>uint256) private table;
    
    Certificate[] public certList;
    //uint256 public certCount;
    
    bytes32[][] public merkleTree;
    
    struct Certificate {
        string domain_name;
        string public_key;
    }
    
    constructor() {
        merkleTree.push();
    }

    // function set(string memory domain_name, uint256 public_key) public {
    //     table[domain_name] = public_key;
    // }

    // function get(string memory domain_name) public view returns (uint256) {
    //     return table[domain_name];
    // }
    
    function getCertHash(Certificate memory cert) internal pure returns (bytes32) {
        // hash all fields in Certificate packed
        return keccak256(abi.encodePacked(cert.domain_name, cert.public_key));
    }
    
    function hashTwoItems(bytes32 item1, bytes32 item2) internal pure returns (bytes32) {
        // put the smaller item at front
        if (item1 <= item2){
            return keccak256(abi.encodePacked(item1, item2));
        } else {
            return keccak256(abi.encodePacked(item2, item1));
        }
    }
    
    function addCertificate(string memory _domain_name, string memory _public_key) public {
        certList.push( Certificate(_domain_name, _public_key) );
        uint index = certList.length -1;
        // add hash of the new certificate to merkleTree
        addItemToTree( getCertHash(certList[index]) );
    }
    
    function updateCertificate(uint256 cert_index, string memory _domain_name, string memory _public_key) public {
        certList[cert_index] = Certificate(_domain_name, _public_key);
        
        // update hash of the certificate in merkleTree
        updateItemInTree( getCertHash(certList[cert_index]), cert_index );
    }
    
    function addItemToTree(bytes32 newitem) public {
        // add item to merkleTree level-0
        merkleTree[0].push(newitem);
        uint index = merkleTree[0].length -1;   // index of newitem in merkleTree[0]
        uint level = 0;
        while (merkleTree[level].length > 1) {
            if (merkleTree.length <= level+1) { // ensure merkleTree[level+1] exists
                merkleTree.push();
            }
            
            uint nextlevel_index = index / 2;
            if (merkleTree[level+1].length <= nextlevel_index) { // ensure merkleTree[level+1][nextlevel_index] exists
                merkleTree[level+1].push();
            }
            
            // since we're adding a new item, merkleTree[level][index] must be the last item in merkleTree[level]
            if (index % 2 == 0) {
                merkleTree[level+1][nextlevel_index] = merkleTree[level][index];
            }
            else {
                merkleTree[level+1][nextlevel_index] = hashTwoItems(merkleTree[level][index-1], merkleTree[level][index]);
            }
            index = nextlevel_index;
            level = level+1;
        }
    }
    
    function updateItemInTree(bytes32 item, uint256 level0_index) public {
        merkleTree[0][level0_index] = item;     // update item in merkleTree[0]
        
        uint index = level0_index;
        uint level = 0;
        while (merkleTree[level].length > 1) {  // while hasn't reached merkleTree root level
            // update corresponding item in merkleTree[level+1]
            
            uint nextlevel_index = index / 2;
            
            if (index % 2 == 0) {
                if (index == merkleTree[level].length-1) {  // if merkleTree[level][index] is the last item in merkleTree[level]
                    merkleTree[level+1][nextlevel_index] = merkleTree[level][index];
                } else {
                    merkleTree[level+1][nextlevel_index] = hashTwoItems(merkleTree[level][index], merkleTree[level][index+1]);
                }
            }
            else {
                merkleTree[level+1][nextlevel_index] = hashTwoItems(merkleTree[level][index-1], merkleTree[level][index]);
            }
            index = nextlevel_index;
            level = level+1;
        }
    }
    
    function getTreeRoot() public view returns (bytes32) {
        return merkleTree[merkleTree.length-1][0];  // there should be only 1 item on merkleTree root level
    }
    
    function getMerkleProof(uint256 level0_index) public view returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](merkleTree.length-1);
        uint index = level0_index;
        uint level = 0;
        uint num_sibling = 0;
        while (merkleTree[level].length > 1) {  // while hasn't reached merkleTree root level
            // get sibling of merkleTree[level][index] in merkleTree[level]
            
            if (index % 2 == 0) {   // index is even
                if (index == merkleTree[level].length-1) { 
                    // merkleTree[level][index] is the last item in merkleTree[level], it has no sibling on this level
                } else {    // sibling is index+1
                    proof[num_sibling] = merkleTree[level][index+1];
                    num_sibling += 1;
                }
            }
            else {   // index is odd, sibling is index-1
                proof[num_sibling] = merkleTree[level][index-1];
                num_sibling += 1;
            }
            index = index / 2;
            level = level+1;
        }
        
        // ensure proof.length == num_sibling
        if (num_sibling == proof.length)
            return proof;
        else {  // construct a new memory array with correct length
            bytes32[] memory proof_array = new bytes32[](num_sibling);
            for (uint i = 0; i < num_sibling; i++){
                proof_array[i] = proof[i];
            }
            return proof_array;
        }
    }
    
    function verifyProof(bytes32 cert_hash, bytes32[] memory proof) public view returns (bool) {
        bytes32 hash = cert_hash;
        for (uint i = 0; i < proof.length; i++) {
            hash = hashTwoItems(proof[i], hash);
        }
        return (hash == getTreeRoot());
    }
    
    function testVerifyCertificate(uint256 cert_index, string memory domain_name, string memory public_key) public view returns (bool) {
        // return (getCertHash(Certificate("hi", "bye")) == getCertHash(Certificate("hi", "bye")));
        // return (merkleTree.length);
        
        // get the proof of certificate at cert_index
        // Certificate(domain_name, public_key) can pass verification if it is identical to certList[cert_index]
        bytes32[] memory proof = getMerkleProof(cert_index);
        bytes32 cert_hash = getCertHash(Certificate(domain_name, public_key));
        return ( verifyProof(cert_hash, proof) );
    }
    
}