# Connecting to the wallet's V3 Owner API from Node

Inspired by: https://github.com/mimblewimble/grin-wallet/blob/master/doc/samples/v3_api_node/


This is a small sample with code that demonstrates how to initialize the Wallet V3's Secure API and call API functions through it.

To run this sample:

First run the Owner API:

```.sh
epic-wallet owner_api
```

Then (assuming node.js and npm are installed on the system):

```.sh
npm install
node src/index.json
```

Feel free to play around with the sample, modifying it to call whatever functions you'd like to see in operation!
