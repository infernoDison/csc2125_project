// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.7.0;

import "./ENS.sol";

/**
 * The ENS registry contract.
 */
contract ENSRegistry is ENS {

    struct Record {
        address owner;
        address resolver;
        uint64 ttl;
        
        // For our project
        uint256 public_key;
        uint32 ipv4_addr;
        uint128 ipv6_addr;
    }
    
    

    mapping (bytes32 => Record) records;
    mapping (address => mapping(address => bool)) operators;

    // Permits modifications only by the owner of the specified node.
    modifier authorised(bytes32 node) {
        address owner = records[node].owner;
        require(owner == msg.sender || operators[owner][msg.sender]);
        _;
    }

    /**
     * @dev Constructs a new ENS registrar.
     */
    constructor() public {
        records[0x0].owner = msg.sender;
    }

    /**
     * @dev Sets the record for a node.
     * @param node The node to update.
     * @param owner The address of the new owner.
     * @param resolver The address of the resolver.
     * @param ttl The TTL in seconds.
     */
    function setRecord(bytes32 node, address owner, address resolver, uint64 ttl) external virtual override {
        setOwner(node, owner);
        _setResolverAndTTL(node, resolver, ttl);
    }

    /**
     * @dev Sets the record for a subnode.
     * @param node The parent node.
     * @param label The hash of the label specifying the subnode.
     * @param owner The address of the new owner.
     * @param resolver The address of the resolver.
     * @param ttl The TTL in seconds.
     */
    function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external virtual override {
        bytes32 subnode = setSubnodeOwner(node, label, owner);
        _setResolverAndTTL(subnode, resolver, ttl);
    }

    /**
     * @dev Transfers ownership of a node to a new address. May only be called by the current owner of the node.
     * @param node The node to transfer ownership of.
     * @param owner The address of the new owner.
     */
    function setOwner(bytes32 node, address owner) public virtual override authorised(node) {
        _setOwner(node, owner);
        emit Transfer(node, owner);
    }

    /**
     * @dev Transfers ownership of a subnode keccak256(node, label) to a new address. May only be called by the owner of the parent node.
     * @param node The parent node.
     * @param label The hash of the label specifying the subnode.
     * @param owner The address of the new owner.
     */
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) public virtual override authorised(node) returns(bytes32) {
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        _setOwner(subnode, owner);
        emit NewOwner(node, label, owner);
        return subnode;
    }

    /**
     * @dev Sets the resolver address for the specified node.
     * @param node The node to update.
     * @param resolver The address of the resolver.
     */
    function setResolver(bytes32 node, address resolver) public virtual override authorised(node) {
        emit NewResolver(node, resolver);
        records[node].resolver = resolver;
    }

    /**
     * @dev Sets the TTL for the specified node.
     * @param node The node to update.
     * @param ttl The TTL in seconds.
     */
    function setTTL(bytes32 node, uint64 ttl) public virtual override authorised(node) {
        emit NewTTL(node, ttl);
        records[node].ttl = ttl;
    }
    
    
    // Functions for our project
    function setPublicKey(bytes32 node, uint256 public_key) public authorised(node){
        emit NewPublicKey(node, public_key);
        records[node].public_key = public_key;
    }
    
    function setIpv4Address(bytes32 node, uint32 ipv4_addr) public authorised(node){
        emit NewIpv4Address(node, ipv4_addr);
        records[node].ipv4_addr = ipv4_addr;
    }
    
    function setIpv6Address(bytes32 node, uint128 ipv6_addr) public authorised(node){
        emit NewIpv6Address(node, ipv6_addr);
        records[node].ipv6_addr = ipv6_addr;
    }
    
    
    function getIpv4ByName(bytes32 node) public view returns (uint32) {
        return records[node].ipv4_addr;
    }
    
    function getIpv6ByName(bytes32 node) public view returns (uint128) {
        return records[node].ipv6_addr;
    }
    
    function getPublicKeyByName(bytes32 node) public view returns (uint256) {
        return records[node].public_key;
    }
    
    
    
    /**
     * @dev Enable or disable approval for a third party ("operator") to manage
     *  all of `msg.sender`'s ENS records. Emits the ApprovalForAll event.
     * @param operator Address to add to the set of authorized operators.
     * @param approved True if the operator is approved, false to revoke approval.
     */
    function setApprovalForAll(address operator, bool approved) external virtual override {
        operators[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /**
     * @dev Returns the address that owns the specified node.
     * @param node The specified node.
     * @return address of the owner.
     */
    function owner(bytes32 node) public virtual override view returns (address) {
        address addr = records[node].owner;
        if (addr == address(this)) {
            return address(0x0);
        }

        return addr;
    }
    

    /**
     * @dev Returns the address of the resolver for the specified node.
     * @param node The specified node.
     * @return address of the resolver.
     */
    function resolver(bytes32 node) public virtual override view returns (address) {
        return records[node].resolver;
    }

    /**
     * @dev Returns the TTL of a node, and any records associated with it.
     * @param node The specified node.
     * @return ttl of the node.
     */
    function ttl(bytes32 node) public virtual override view returns (uint64) {
        return records[node].ttl;
    }

    /**
     * @dev Returns whether a record has been imported to the registry.
     * @param node The specified node.
     * @return Bool if record exists
     */
    function recordExists(bytes32 node) public virtual override view returns (bool) {
        return records[node].owner != address(0x0);
    }

    /**
     * @dev Query if an address is an authorized operator for another address.
     * @param owner The address that owns the records.
     * @param operator The address that acts on behalf of the owner.
     * @return True if `operator` is an approved operator for `owner`, false otherwise.
     */
    function isApprovedForAll(address owner, address operator) external virtual override view returns (bool) {
        return operators[owner][operator];
    }
    

    function _setOwner(bytes32 node, address owner) internal virtual {
        records[node].owner = owner;
    }

    function _setResolverAndTTL(bytes32 node, address resolver, uint64 ttl) internal {
        if(resolver != records[node].resolver) {
            records[node].resolver = resolver;
            emit NewResolver(node, resolver);
        }

        if(ttl != records[node].ttl) {
            records[node].ttl = ttl;
            emit NewTTL(node, ttl);
        }
    }
    
    /**
     * @dev String compare
     */ 
    function _strcmp(string memory a, string memory b) internal returns(bool){
        return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked(b)));
    }
    
    function _setPublicKey(bytes32 node,  uint256 public_key) internal{
        
        if (public_key != records[node].public_key){
            records[node].public_key = public_key;
            emit NewPublicKey(node, public_key);
        }
    }
    
    function _setIpAddress(bytes32 node, uint32 ipv4_addr, uint128 ipv6_addr) internal{
        if(ipv4_addr != records[node].ipv4_addr){
            records[node].ipv4_addr = ipv4_addr;
            emit NewIpv4Address(node, ipv4_addr);
        }
        
        if (ipv6_addr != records[node].ipv6_addr){
            records[node].ipv6_addr = ipv6_addr;
            emit NewIpv6Address(node, ipv6_addr);
        }
    }
}
