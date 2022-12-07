### HOW TO INSTALL ###
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
Please read carefully before changing this values.
epic-wallet.log is the log file for wallet processes. If there are errors
or other issues this will be written in the log file.

### HOW TO UPGRADE ###
1. make a backup of your wallet_data folder (default location is ~/.epic/main)
2. replace epic-wallet(.exe)
3. remove epic-wallet.toml
4. init the wallet to create a new epic-wallet.toml see step 2.

### HOW TO SETUP ###

### Run epic-wallet in default user homedir (~/.epic)
1. open a terminal/cmd and move to location of the epic-wallet(.exe) binary.
   (Tip) on Windows you can type "cmd" and hit enter in the File-Explorer Address bar. This will open a new terminal in the current directory.
   On Mac you can drag and drop the folder into the terminal, which copies the path from this folder
2. init the wallet with:
   Linux/Mac $./epic-wallet init
   Windows: epic-wallet.exe init
   ... follow the instructions in terminal


### Run epic-wallet in a custom dir
1. Open a terminal/cmd and move to location of the epic-wallet(.exe) binary.
   (Tip) on Windows you can type "cmd" and hit enter in the File-Explorer Address bar. This will open a new terminal in the current directory.
   On Mac you can drag and drop the folder into the terminal, which copies the path from this folder
2. Init the wallet with:
   Linux/Mac $./epic-wallet init -h
   Windows: epic.exe init -h
   ... follow the instructions in terminal
3. Recover a wallet:
   Linux/Mac $./epic-wallet init -r -h
   Windows: epic.exe init -r -h
   ... follow the instructions in terminal
