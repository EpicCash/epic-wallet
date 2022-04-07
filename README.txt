Table of Contents:
I. 	WARNINGS
II. 	DEPENDENCIES
III. 	TOR SETUP
IV. 	HOW TO INSTALL CLI WALLET
V.	CLI WALLET USER HANDBOOK
VI. 	CREDITS

I. 	***WARNINGS***
	Command "scan -d" is typically NOT executed by exchanges or pools because this kills all transactions rather they are new pending transactions or old failed transactions. This option is usually for enduser wallets who are not 		processing additional customer transactions.

	You must use "scan --start_height 0" to start scanning the complete blockchain from zero. Otherwise, the scan function will only use the last 1000 outputs

	If you have "unconfirmed" and number of confirms is zero then take the Tx number and try a repost with "./epic-wallet repost -i [TX ID]" If the repost fails you will see an error message you can cancel this transaction. This will 	keep your outputs clean without make a "scan -d"

	Please read and learn the commands from Section V. "CLI Wallet User Handbook" after the installation procedures. 


II. 	###DEPENDENCIES###

	Sync'd EPIC Server Node. Download EPIC server node from https://epic.tech/downloads/ and follow instructions to sync the node before proceeding.

	TOR: Not mandatory but preferrable to avoid port forwarding configuration or ngrok account setup/use. Follow steps below to install TOR

III. 	### TOR SETUP ### 

	To use TOR to receive and send EPIC you must install the TOR client on your system.
	After installing the tor client you can find your tor address with:

	$ ./epic-wallet.exe address (linux/mac/powershell) or $ epic-wallet.exe address (windows command prompt)

	output:

	TOR Onion V3 Address for account - default
	-------------------------------------
	wnafpa4bauycvh6ael4gtgpgf7afr7a5tunsqrbicdqvaos3heklbqqd <--- this is your tor address

	### FOR LINUX ###
	To install TOR-Client on Linux System open a Terminal and execute: $ sudo apt install tor

	### FOR MAC ###
	To install TOR-Client on your Mac you can read this simple HowTo: https://deepdarkweb.github.io/how-to-install-tor-on-macos-tutorial/

	### FOR WINDOWS ###
	1. Go to: https://www.torproject.org/download/tor/ and Download the "Windows Expert Bundle"
	2. Unzip the folder.
	3. Copy all files within the "Tor" folder in the epic-wallet.exe directory.
	   The folder structure should look like this:
      	epic-wallet.exe
      	libcrypto-1_1.dll
      	libevent_core-2-1-7.dll
      	libevent_extra-2-1-7.dll
      	libevent-2-1-7.dll
      	libgcc_s_dw2-1.dll
      	libssl-1_1.dll
      	libssp-0.dll
      	libwinpthread-1.dll
      	tor.exe
      	tor-gencert.exe
      	zlib1.dll

IV.	### HOW TO INSTALL CLI WALLET ###
	The epic binaries can be executed from any location of your computer.
	No special installation process is required to use them.
	On the first run the epic-wallet creates some files and folder.
	The default location of this files are located in your user homedir as a hidden 
	Directory "~/.epic/main" 

	This files are:
	wallet_data/
	epic-wallet.toml
	epic-wallet.log

	The wallet_data/ folder is the wallet database with your wallet seed
	epic-wallet.toml is the configuration file for the wallet.
	You will find a short descpription of this settings as comments starting with a "#".
	Please read carefully before changing these values.
	epic-wallet.log is the log file for wallet processes. If there are errors or other issues this will be written in the log file.

	### HOW TO UPGRADE ### 
	1. make a backup of your wallet_data folder (default location is ~/.epic/main)
	2. replace epic-wallet(.exe)
	3. remove epic-wallet.toml
	4. init the wallet to create a new epic-wallet.toml see step 2 in "HOW TO SETUP" below.
	
	### HOW TO SETUP ###

	### Run epic-wallet in default user homedir (~/.epic)
	1. open a terminal/cmd and move to location of the epic-wallet(.exe) binary.
	   (Tip) on Windows you can type "cmd" and hit enter in the File-Explorer Address bar. This will open a new terminal in the current directory.
	   On Mac you can drag and drop the folder into the terminal, which copies the path from this folder
	2. init the wallet with:
	   Linux/Mac $./epic-wallet init
	   Windows: epic-wallet.exe init
	   ... follow the instructions in terminal
	3. open another terminal/cmd and move to location of the epic-wallet(.exe) binary and start the listener with:
	   Linux/Mac $./epic-wallet listen
	   Windows: epic-wallet.exe listen (command prompt) or ./epic-wallet listen (powershell)



	### Run epic-wallet in a custom dir
	1. Open a terminal/cmd and move to location of the epic-wallet(.exe) binary.
	   (*~*PRO-Tip*~*) on Windows you can type "cmd" and hit enter in the File-Explorer Address bar. This will open a new terminal in the current directory.
	   On Mac you can drag and drop the folder into the terminal, which copies the path from this folder
	2. Init the wallet with:
	   Linux/Mac $./epic-wallet init -h
	   Windows: epic.exe init -h 
	   ... follow the instructions in terminal
	3. Recover a wallet:
	   Linux/Mac $./epic-wallet init -r -h
	   Windows: epic.exe init -r -h
	   ... follow the instructions in terminal
	4. open another terminal/cmd and move to location of the epic-wallet(.exe) binary and start the listener with:
	   Linux/Mac $./epic-wallet listen
	   Windows: epic-wallet.exe listen (command prompt) or ./epic-wallet listen (powershell)
	
V.	CLI WALLET USER HANDBOOK
	Now that you've set up your fully sync'd node and wallet, let's get to know the wallet. The following document is an extremely comprehensive user guide to the reference epic wallet implementation, epic-wallet.

	File Structure
	By default, epic will create all wallet files in the hidden directory .epic under your home directory (i.e. ~/.epic/main). You can also create and use a wallet with data files in a custom directory, as will be explained later.

	A epic wallet maintains its state in an Lightning Memory-Mapped Database (LMDB), with the master seed stored in a separate file. When creating a new wallet, the file structure should be as follows:

	[wallet directory]
	├── epic-wallet.log
	├── epic-wallet.toml
	├── tor
	└── wallet_data
	    ├── db
	    │   └── lmdb
	    │
	    └── wallet.seed
	
	epic-wallet.toml contains configuration information for the wallet. You can modify values within to change ports, the address of your epic node, or logging values.

	wallet.seed is your master seed file; the private keys of all your outputs are derived from it, and its contents are encrypted with your wallet password. The seed file can be recovered using the seed phrase.

	tor folder contains Tor configuration files used by the wallet listener. There should be no need to manipulate anything in this directory manually.

	help, This will display all the commands and every global flag:
	
	epic-wallet help 
	
	To get additional info about a specific command type epic-wallet help [command]
	e.g: epic-wallet help send
	You can also pass --help or -h.

	init, Before doing anything else, the wallet files need to be generated via the init command:

	epic-wallet init
	You'll be prompted to enter a password for the new wallet. It will be used to encrypt your master.seed file and you'll be asked to type it for most wallet commands.

	By default, your wallet files will be placed into ~/.epic/main. Alternatively, if you'd like to run a wallet in a directory of your choice, you can create one in the current directory by using flag -h, e.g:

	epic-wallet init -h
	This will create all the needed data files, including epic-wallet.toml and wallet.seed, in the current directory. When running any epic-wallet command, epic will check the working directory if these files exist. If not, it will 		use the default location ~/.epic.

	Upon a successful init, the wallet prints a 24-word recovery phrase, which you should write down and store in a non-digital format. This phrase can be used to re-create your master seed file if it gets lost or corrupted, or if 		you forget the wallet password.

	If you'd prefer to use a 12-word recovery phrase, you can use the -s --short_wordlist flag.

	init --recover
	If you need to recreate your wallet from an existing seed, you can init a wallet with a recovery phrase using the -r --recover flag. For example, the following command initializes a wallet in the current directory.


	epic-wallet init -hr

	File /home/tomriddle/wallet/epic-wallet.toml configured and created
	Please enter your recovery phrase:
	On the first run, the wallet will scan the entire chain and restore any outputs that belong to you.

	account
	The account command is used to manage wallet accounts. Let's print a list of your existing accounts:


	epic-wallet account
	Accounts could be thought of as somewhat similar to different bank accounts under the same name. Each account acts as a separate wallet, but they are all derived from the same master seed. The default account is created when you 		initialize the wallet.

	To create a new account, pass the argument -c --create.


	epic-wallet account -c jedusor
	This will create a new account called 'jedusor'.

	All epic-wallet commands can then be passed the argument -a to specify an account for the command (otherwise default account is used), e.g:
	

	epic-wallet -a jedusor info
	info
	The info command summarizes wallet account balance.


	epic-wallet info

	____ Wallet Summary Info - Account 'default' as of height 813137 ____

	Confirmed Total                  | 5779.473029600
	Awaiting Confirmation (< 10)     | 0.000000000
	Awaiting Finalization            | 139.851133700
	Locked by previous transaction   | 389.859133700
	-------------------------------- | -------------
	Currently Spendable              | 5779.473029600
	Confirmed Total is your balance including both spendable coins and those awaiting confirmation.
	Awaiting Confirmation denotes the balance from transactions that have appeared on-chain, but for which your wallet is waiting a set number of blocks before treating them as spendable (default is 10 blocks).
	Awaiting Finalization is the balance from transactions that have not yet appeared on-chain. This could be due to the other party not having broadcast the transaction yet. Also, when you are the sender of a transaction, your 		change output will be denoted in this field as well.
	Locked by previous transaction shows the amount of coins locked by a previous transaction you have made and that is currently awaiting finalization. This is usually made up both of the amount being sent and of the change outputs 		waiting to be returned back to your wallet.
	Once the transaction appears on-chain, this balance unlocks and the output that was used will again become available for spending.

	address, To get your wallet address, enter the address command.

	epic-wallet address

	epic1chv9p4uxp3qgl6qp4w6x5p2434varqwl6fdevg6342qr
	This command outputs the same address as using the listen command. The address serves a triple purpose:

	If Tor is available, it will serve as your Tor onion address.
	A key to encrypt the slatepack messages exchanged between you and your counterparty (more on that below).
	Payment proof identification.

	This is not the same concept of address that other cryptocurrencies might use; A Mimblewimble chain has no addresses. It is used purely for wallet to wallet communication.

	listen, The listen command opens up a Tor listener.

	epic-wallet listen
	
	This will automatically configure a Tor hidden service and makes the wallet listen to it for incoming transactions. This allows you to transact directly through Tor with other users who are sending epics to your epic1.... Your 		wallet will listen for requests until the process is cancelled (<Ctrl-C>).

	tor or tor.exe need to be available on the system path.

	send, The send command is the first step of building an interactive transaction. The transaction can either be an instant synchronous exchange through Tor, or it can be an asynchronous process, in which each step is done manually 	by exchanging easily copy-pastable strings called slatepacks.
	
	The choice between the two methods is handled automatically by using send in the form of send -d <address> <amount>.

	epic-wallet send -d epic1dhvv9mvarqwl6fderuxp3qgl6qpphvc9p4u24347ec0mvvg6342q4w6x5r 180
	This command tries to send 180 epics to the specified address via Tor. If both wallets are accessible, the transaction would complete immediately with no further steps required.

	If the above communication fails, for whatever reason, your wallet will output a slatepack message:


	BEGINSLATEPACK. HctgNGXrJDGFY3B KrEF1meAezGjxQ6 Z93QF6Ps2m9yKCQ LfhZvpDY9ZXViM7 nDoNeMvwtYV2crr 8gDqvYDmtRfLL3n Uabao7VyWR4AuYg TXQUSWU83kEhKmr bRtdRjvpisx1LYo 9cyZGfsgsd7ZvDJ KKZPHhcPe4Eivtv cMvee3nwFFY3ZnM SoULNaHVJ38h3tZ 		vMXQMoMLB17L53o Xy6QQjDaG8avUBt LQq2GfGRTiUPQgn vQwFzfZPVzVKNLk
	5AFmUQFZtiVdTJV xHvc1BuAqcamerv Y76KVccPY3WGupy 4zWFpkjTH65XNiH XqQnkb3EA1iVrHc tyTJ1PWb6X6oV1k ktYiWBpatyTirRy CywPyjr6c8XLr4Q 9VoCedU5BcdFdMB ACqQTwjgVXqjHoS 58ZPKFitjeH67Ts ah6twcKtMaFmTXD i7JEQ7qV6cewgxH 2jwWFxbb98mye6A 		Lm9movc6Wer26L2 91WQD3cbVpAZLEs APFPtyxnWjv8n3W
	ZXFLR2TPZwGc5Vt zwFUPoyWfKXasQy VVV6tbKWEEhqAZR e34M7uEwfurpUUi 9812VFPY1qw3K9b ynwQXuXMuWQCUnU s1JqWqFgSQKENUP tGCK19dys9twghA FaAc7ZXQHdMbUoL sVxVfdjE94F1Wpj M7QAM5VZuaauHdQ Mt2erFyxJ5vsYSZ hgS553UKoQL5YWX E7oRNdMDkJV6VkL 		i55kAQc1vWvW9ce 3MoXiBT4TJ1SyNS NVZKxgk8c. ENDSLATEPACK.
	This message contains the data required for the receiver's wallet to process the transaction via the receive command. This slatepack is also encrypted for the recipient only, since you provided an address (which is a public key) 		by using the -d flag.

	Non-encrypted slatepack

	If the receiver does not want, or is not able to provide an address, you could use command send without the -d --dest flag.

	epic-wallet send 180
	In this case, the wallet will simply output a non-encrypted slatepack message which can be sent to anybody.

	more flags
	-m --manual if present, don't attempt to interact via Tor, only output slatepack message.
	-f --fluff if present, ignore the dandelion relay protocol. Dandelion bounces your transactions directly through several nodes in a stem phase, after which the transaction randomly fluffs (broadcast) to the rest of the network.
	-n --no_payment_proof if present, do not request the data required for a payment proof. This shortens the slatepack message length.
	-e --estimate-selection if present, performs a "dry-run" of creating the transaction, without actually doing anything and locking the funds. It then lists different output selection strategies (outlined below) and their possible 		effect on your wallet outputs, if chosen.
	-s --selection allows you to choose between two output selection strategies, small and all. The default strategy is small, which includes the minimum number of inputs to cover the amount, starting with the smallest value output. 		In contrast, using all consolidates all of your outputs into a single new output, thus reducing your wallet size, increasing operation speed and reducing the UTXO-set size of the chain. The downside is that the entire contents of 	your wallet remain locked until the transaction is validated on-chain, and all outputs are linked to one another, a detriment to your privacy.
	-b --ttl_blocks allows you to specify a number of blocks into the future, after which a wallet should refuse to process the transaction further. This can be useful for putting time limits on transaction finalization, but please 		note this is not enforced at the epic protocol level; it's up to individual wallets whether they wish to respect this flag.
	receive
	The receive command processes the slatepack message provided by the sender.


	epic-wallet receive
	After entering the command, you'll be prompted to input the slatepack.
	Then your wallet will output another slatepack message to provide the other party, so they can finalize the transaction.

	Files

	When sending or receiving via slatepacks, the wallet will also create a text file containing the message it generated. Default path is ~/.epic/main/slatepacks.

	To receive epics using a file, type:


	epic-wallet receive -i $PATH/file.tx
	finalize
	The finalize command is the final step to any slatepack transaction.


	epic-wallet finalize
	After entering the command, you'll be prompted to input the slatepack message provided to you by the receiver.

	The transaction building process will then be finalized and your wallet will post it to the network.

	If the flag -n --nopost is present, the transaction would be finalized but not posted.

	post
	Manually post a finalized transaction to the network. Either type epic-wallet post and enter the slatepack message into the prompt, or specify the file path using the -i flag.


	epic-wallet post -i "~/.epic/main/slatepacks/my_tx.S3.slatepack/"
	proof
	epic's privacy and scalability mechanics mean users no longer have the ability to simply prove a transaction has happened by pointing to it on the chain. By default, whenever a transaction sent to a destination address using -d, 		a payment proof is created.

	Payers can then use these proofs to resolve future payment disputes and prove they sent funds to the correct recipient.

	The sender can export the payment proof by specifying the transaction id (-i) (obtained by txs) or the tx-UUID (-t), and choosing the path for the proof file, e.g:


	epic-wallet export_proof -i 4 "~/Documents/proof.txt"
	The sender can then provide this proof to any other wallet for verification.

	Verification for e.g.


	epic-wallet verify_proof $PATH/proof.txt
	This will ensure that:

	The kernel for the transaction in the proof is validated and can be found on-chain.
	Both the sender and recipient's signatures correctly sign for the amount and the kernel.
	On top of that, if the receiver's address in the transaction belongs to the same wallet who's verifying, then the user will be informed as follows:

	epic-wallet verify_proof proof.txt

	Payment proof's signatures are valid.
	The proof's recipient address belongs to this wallet.
	Command 'verify_proof' completed successfully
	invoice
	The invoice command sends an invoice transaction, in which the initiator requests an amount for payment and sends that request to another party.
	
	Since invoice transactions require manual confirmation from the party paying the funds, they can only be created and sent to payers via slatepack.


	epic-wallet invoice -d epic1dhvv9mvarqwl6fderuxp3qgl6qpphvc9p4u24347ec0mvvg6342q4w6x5r 60
	This command will create an encrypted (since -d is provided) invoice, requesting a payment of 60 epics. The resulting slatepack can then be sent to the other party for them to pay.

	Upon receiving the back the slatepack from the payer, the transaction can then be finalized and posted using the finalize command.

	pay
	After receiving an invoice request, the payer can use the pay command to decode (also decrypt if possible) the slatepack and confirm the amount of coins being requested as payment.


	epic-wallet pay

	Please paste your encoded slatepack message:
	BEGINSLATEPACK. P9rVoTRyKdhVsuC a5SfwQMXbtsDBwD omfeWYWwkbK9AUD k2pZvpgeXmJSUcv y9Mi81ngsCrpW9r QW226CWwbxrSprJ cCJA9cACpguBHDj eExN8vuYc1SHj9B 2Xa1BPGB77kpY9q uG9eXmaeprY6CQt PAibwfMnwxVDJFU EeQfwwSnEUADkg3 wBYXcuSVTnfJ4Jj 		DnqawMkmAiWvhNm WLrdZ1Vh3P6TXP6 ZgJG9pRNi51mAtU 9soyVAgvFWoEpgn VA6suegVxTsWN1r V3LQHB7bjwX5Rwa yPfqhGTLwR. ENDSLATEPACK.

	This command will pay the amount specified in the invoice using your wallet's funds.
	After you confirm, the following will occur:

	* 10.000000000 of your wallet funds will be added to the transaction to pay this invoice.
	* The wallet will IMMEDIATELY attempt to send the resulting transaction to the wallet listening at: 'epic1ln4y82fw4urggk3hq0xkeqfhw3dfe6rhcv6a0v64uz4ny9epcc6qpuwx4k'.
	* If other wallet is not listening, the resulting transaction will output as a slatepack which you can manually send back to the invoice creator.

	Please review the above information carefully before proceeding

	To proceed, type the exact amount of the invoice as displayed above (or Q/q to quit) >
	To confirm the payment, type the exact amount in decimal, 10.000000000 in this example, into the prompt. Your wallet will then fill out the transaction slate and return a slatepack for you to provide back to the initiator, which 		they can then finalize.

	epic-wallet outputs

	Wallet Outputs - Account 'default' - Block Height: 814491
	---------------------------------------------------------------------------------------------------------------------------------------------------------------
	 Output Commitment                                                   MMR Index  Block Height  Locked Until  Status   Coinbase?  # Confirms  Value           Tx
	===============================================================================================================================================================
	 08f4f062b99223d2d8a1ad1ae11085ab2d7b4f1bc603f9c29748f1b918861fdf23  7498573    743936        743936        Unspent  false      70556       5198.081029600  1
	---------------------------------------------------------------------------------------------------------------------------------------------------------------
	 097fe8bf1ad6a792600d5e010d0b77c40b147ea122c176476259f100a48924d40c  7832632    790025        790025        Unspent  false      24467       581.392000000   2
	---------------------------------------------------------------------------------------------------------------------------------------------------------------
	 08645896f150bfc70f36a602a7a5f41180ae8d5db42864f19f7257542cf2c7fc98  None       811501        0             Unspent  false      2991        389.859133700   9
	---------------------------------------------------------------------------------------------------------------------------------------------------------------
	By default, only unspent outputs are listed. To show spent outputs, provide the -s flag.


	epic-wallet -s outputs
	txs
	Every time an action is performed in your wallet (send, receive, even if uncompleted), an entry is added to an internal transaction log containing vital information about the transaction. Because the epic blockchain contains no 		identifying information whatsoever, this transaction log is necessary for your wallet to keep track of transactions. To view the contents of your transaction log, use the command:


	epic-wallet txs

	Transaction Log - Account 'default' - Block Height: 814448
	-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------		------------------------------------------------
	 Id  Type         Shared Transaction Id                 Creation Time        TTL Cutoff Height  Confirmed?  Confirmation Time    Num.    Num.     Amount        Amount       Fee    Net           Payment   Kernel                                                              Tx
                                                                                                                                 Inputs  Outputs  Credited      Debited             Difference    Proof                                                                         Data
							===================================================================================================================================================================================================================================		 0   Received Tx  2b2ffc5e-8fa0-4450-b270-078df29b3e23  2020-07-28 13:18:18  None               true        2020-07-28 13:18:18  0       1        389.892       0.0          0.007  389.892       None      				ddec166399348a24d2893c025b4b4d4a058f81834a663284ba23fe0bd0ac025b4b  Yes
	-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------		------------------------------------------------
	 1   Sent Tx      fd9b3035-73d0-4ea3-8c3e-5d45c512ad8b  2020-08-03 15:32:19  None               true        2020-08-03 15:42:20  2       1        389.8591337   390.8661337  0.007  -1.007        Yes       				0834a66310df8a8b43093c025b4b4d4a058f8188ee24d2809e338e0bd0ae9e2c2c  Yes
	-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------		------------------------------------------------
	 2   Sent Tx      ea92fcce-8fa0-48d0-b270-078df2e22d24  2020-08-04 18:51:47  None               false       None                 1       1        139.8511337   389.8591337  0.008  -250.008      None      			09fd95b4e40ce1c2d67376d46dc37ddec1aa0ae50ca9934ba271fff0b47510c72f  Yes
	   - Cancelled
	-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------		To see the inputs & outputs associated with a particular transaction, as well as the payment proof associated with the transaction, use the -i switch and specify the id of the transaction, e.g:


	epic-wallet txs -i 0

	cancel, Cancels an in-progress created transaction, freeing previously locked outputs for use again.

	epic-wallet cancel -i 2
	To specify which transaction to cancel, use the -i flag along with the tx id (obtained by txs) or the -t flag with the tx-UUID.

	scan, The scan command scans the entire UTXO (unspent tx outputs) set from the node, identifies which outputs are yours and updates your wallet state.


	epic-wallet scan
	It should not be necessary to run the scan command manually, as the wallet continually scans the outputs on the chain. However, if for some reason you believe your outputs and transactions are in an inconsistent state, you can 		initiate a manual scan to attempt to fix or restore them.

	flags

	-d --delete-unconfirmed if present, scan and cancel all pending transactions, freeing up any locked outputs.

	-h --start-height lets you specify a block height from which to start the manual scan.

	When initializing a wallet from an existing seed via the epic-wallet init -r command, this scan is performed automatically on the first run.

	recover, The recover command displays the existing wallet's 24 (or 12) word seed phrase.


	epic-wallet recover
	arguments
	There are several global wallet arguments which you can provide for every command.

	account, To set the account for a wallet command, provide the -a argument.


	epic-wallet -a jedusor info
	password
	You could specify your password on the directly command line by providing the -p argument. Please note this will place your password in your shell's command history, so use this switch with caution.


	epic-wallet -p mypass info
	node
	The wallet needs to talk to a running epic node in order to remain up-to-date and verify its contents. By default, it tries to contact a node at 127.0.0.1:3413. To change this, either modify the value in the epic_wallet.toml 		file, or alternatively, you can provide the -r (server) switch to wallet commands.


	epic-wallet -r "http://192.168.0.2:3413" info

VI. 	CREDITS

	The CLI handbook was forked from https://docs.grin.mw/getting-started/wallet-handbook
	Thanks to the Epic Cash community of developers for everything else!



	



