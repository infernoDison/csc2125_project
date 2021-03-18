// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Key_Domain_Storage {
    
    mapping(string =>uint256) private table;
    
    struct Certificate{
        string common_name;
        string organization;
        
        //validity period
        
    }

    function set(string memory domain_name, uint256 public_key) public {
        
       table[domain_name] = public_key;
    }

    function get(string memory domain_name) public view returns (uint256) {
        return table[domain_name];
    }
}