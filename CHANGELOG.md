# epic-wallet 3.2.2-alpha-1

  - [#20](https://github.com/EpicCash/epic-wallet/issues/20) Fix: wrong balance after the recovery process
  - Feat: Emoji transaction method
  - [#26](https://github.com/EpicCash/epic-wallet/issues/26) Add -f,--show_full_history to output history
  - Fix: Unwrap error on empty password for keybase listener

# epic-wallet 3.0.0

  - Fix: owner_rpcs verify and payment proof tests
  - Code: rust format code rustfmt
  - Fix: cargo test and ./api cargo test
  - Update build.md
  - Create build.md
  - Add README.txt to epic-wallet (CLI) github repo and udpate readme.txt to include steps to start listener
  - Update issue templates
  - Add -c flag; update required node version to 3.0.0
  - [#14](https://github.com/EpicCash/epic-wallet/issues/14) fixing unwrap error on password prompt
  - Fix: update epic_util dependency to include fix for the incompatibilty with v2 log-level values on configuration file
  - [#11](https://github.com/EpicCash/epic-wallet/issues/11) Reusing the BlockFees structure from epic core
  - Add missing export and verify proof
  - Update doc and cleanup doc
  - Remove libs from doc
  - Fix: start improve controller unit tests
  - Fix: some unit api tests
  - Code: formatting
  - [#8](https://github.com/EpicCash/epic-wallet/issues/8) Add sample code to simulate a encrypted transaction with init_secure_api (v3)
  - [#7](https://github.com/EpicCash/epic-wallet/issues/7) Update epic cargo docs and wrong comments in code
  - [#6](https://github.com/EpicCash/epic-wallet/issues/6) Removing verifier caches; update epic dependencies
  - Final wallet release v3.0.0 for epic v3.0.0
  - Finalize beta testing
  - Change epic source to 3.0.0-alpha-5
  - Make libwallet slate public


# epic-wallet 3.0.0-alpha-3

  - Change epic source to 3.0.0-alpha-5
  - Make libwallet slate public
  - [#5](https://github.com/EpicCash/epic-wallet/issues/5) Merge: pull request from EpicCash/fix-cargo-tests
  - Fix: wallet default tests
  - Fix: rpc api tests
  - Fix: fixing rpc tests
  - Add cargo lock
  - [#1](https://github.com/EpicCash/epic-wallet/issues/1) Merge pull request from EpicCash/fix-proof-version
  - Fix: github url
  - Fix: proof version

# epic-wallet 3.0.0-alpha-2

  - Fix: conflict with epic server
  - Now cargo install also produces a .crates2.json artifact.
  - Updating references to the server.

# epic-wallet 3.0.0-alpha-1

  - Add config for debian package
  - Fix: header version
  - Add build foundation
  - Update wallet to use new tx proof
  - Integrates with grin 3.0.0


# epic-wallet 2.3.0-1

  - Adequating the tests
  - Fix: foundation.json path
  - Fix: wallet tests
  - Enabling CI.
  - Changing dependencies to git
  - Fix: some rpc tests
  - Using HTTPS for git dependencies
  - Changing the CI jobs.
  - Adding integration to the workspace.
  - Remove integration tests from CI.
  - Fix: more api tests
  - Fix: more rpc tests
  - Adding the API tests back to the CI.
  - Per job cache.
  - Fix: finalize_tx test
  - Fix: all wallet tests
  - Adding a user guide.
  - Owner API usage guide.
  - Add transactions strategies to deal with multiple people
  - Improving the owner_api_usage.
  - Adding state diagrams to explain the issue.
  - Trying to add inlined images.
  - Using png instead of svg
  - Trying to use an embedded image.
  - A Guide to Fixing the 500 Error in the Wallet.
  - Add instructions for CLI users
  - Add support to V2 API responses in the CLI send
  - Change to API 2.0 on CLI send sync
  - Improve the message of error on seed recover


# epic-wallet 2.2.2-1

  - Release version


# epic-wallet 2.0.0-1

  - Fix: copyright notices.


# epic-wallet 1.6.0-2

  - Fix: debian/control description


# epic-wallet 1.6.0-1

  - Add windows installer


# epic-wallet 1.2.0-1

  - Update the rewards to match the whitepaper
  - Fix: indentation
  - Updating bigint
  - Aborting package build in case of error.


# epic-wallet 1.0.2-1

  - Updating with the epic node


# epic-wallet 1.0.0-2

  - Fix: dependencies
  - Removing the pipe from the network


# epic-wallet 1.0.0-1

  - Initial release
  - Merge branch 'master' of https://github.com/mimblewimble/grin-wallet
  - Add doc
  - Fix: compile error
  - travis release
  - travis api token
  - travis build
  - ignore doc tests for now to avoid circular deps
  - add skeletal readmore
  - compile from github branch, clean up cargo dep files
  - move api into separate crate, integration tests working
  - full compilation, move tests into different directory
  - move wallet into refwallet crate
  - initial commit
