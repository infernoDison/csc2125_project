# off-chain-pki

A prototype of a blockchain-based public key infrastructure (PKI). A universal Merkle tree accumulator is used to allow on-chain verification of entries stored off-chain.

## Setup
1. Install `geth`, `solc`, and `web3.py`
2. Build the contract: `$ ./build.sh`
3. Start `geth` locally: `$ geth --dev --datadir data`
4. `local_acc` is a wrapper that deploys `AccVerifier.sol` locally, e.g.
```
$ python3
>>> import local_acc
>>> acc = local_acc.LocalAcc()
>>> acc.add_entry(...)
...
```
