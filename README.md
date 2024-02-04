## Chainless

Here are all the smart-contracts used by Chainless.

- **ChainlessPermissionedSwap**: A contract to buy and sell RWA tokens requiring permission from Chainless.
- **Paymaster**: A contract that charges gas fees from Account Abstraction users using an ERC20 token.

## Cloning

Submodules may download the entire history, to shallow clone them execute one of the following commands.

When cloning the repository for the first time make sure you also initialize the submodules:
```sh
git clone --recurse-submodules --shallow-submodules
```

If you have not cloned using the above flag, you can shallow clone the submodules with this:
```sh
git submodule update --init --recursive --depth=1
```

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/ChainlessPermissionedSwap.s.sol:ChainlessPermissionedSwapScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
