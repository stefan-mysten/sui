# Description

A basic faucet that is intended to be run locally. It does not support heavy loads as it's designed to work locally in a simple and basic way: request a coin, get a coin.

# Quick start

**Prerequisites**

You need to have a key with SUI.

**Starting the faucet as a standalone service**

When starting the faucet as a standalone service, you will need to ensure that the active key in `~/.sui/sui_config/sui.keystore` has enough SUI.

**Starting as part of a local network**

If you're starting this as part of a local network by using `sui start`, then it should automatically find the coins in the configured wallet. If `--force-regenesis` is passed, the wallet
will be funded when the network starts and should have plenty of SUI to get you started.
