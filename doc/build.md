# Epic Wallet - Build, Configuration and Running

## Requirements

**The requirements for building the wallet are the same from the epic server. You can check them in the topic [Requirements](https://github.com/EpicCash/epic/blob/master/doc/build.md#requirements) in the Epic server build instructions.**

## Build steps

```sh
git clone https://github.com/EpicCash/epic-wallet
cd epic-wallet
git submodule update --init --recursive
cargo update
cargo build --release
```

The epic wallet can also be built in debug mode (without the `--release` flag, but using the `--debug` or the `--verbose` flag).

## What was built

A successful build gets you:

* `target/release/epic-wallet` - the main epic wallet binary

## Running the Epic Wallet

**To run the epic-wallet, you also need an epic server running.**

- Instruction of how to run the epic server using the .deb package can be found in the topic [Running the Epic Server](https://github.com/EpicCash/epic/blob/master/doc/running.org#wallet_server).
- If you want to build it from source code, instructions can be found [here](https://github.com/EpicCash/epic/blob/master/doc/build.md).

If you want to execute the epic wallet, in the root directory of your Epic Wallet installation open a new terminal session and execute the following steps:

 1. Navigate to where your epic-wallet binary was generated using the following command:

    ```sh
    cd target/release
    ```

 2. Configuring the **$PATH** environment variable

   ```sh
    export LD_LIBRARY_PATH=$(find . -iname librandomx.so | head -n 1 | xargs dirname | xargs realpath)
   ```

 3. If this is the first time executing the Epic wallet, you must initialize it first. This process will initialize your wallet’s database and create your secret master seed file. For this, we need to run the following command in the terminal:
  
    ```sh
    ./epic-wallet init
    ```

      More information about the wallet initialization can be found in the topic [Initialize the Wallet](https://github.com/EpicCash/epic/blob/master/doc/running.org#initializing-from-a-custom-directory).

4. After you have initialized your wallet, you can run it in listening mode executing the following command in the terminal:

      ```sh
      ./epic-wallet -e listen 
      ```

      More information about the epic wallet listening mode can be found in the topic [Running the wallet API](https://github.com/EpicCash/epic/blob/master/doc/running.org#running-the-wallet-api).
