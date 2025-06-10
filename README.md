# HealthShare
A lightweight permissioned and decentralized healthcare application that implements Attribute Based Access Control (ABAC) using HyperLedger Fabric (Fablo - https://github.com/hyperledger-labs/fablo/blob/main/README.md)  

Clone/locally save this repository on your Linux machine. Create another folder (not inside HealthShare) and in that directory (for example: cd Desktop/App) run the below commands (on Command Line Prompt):  

nvm install 12.22.12  
nvm use 12.22.12  
npm install -g npm@6.14.17  
rm -rf node_modules package-lock.json  
npm install  
sudo apt-get update  
sudo apt-get install -y build-essential python3  

Once you have these installed, execute the below commands:
sudo curl -Lf https://github.com/softwaremill/fablo/releases/download/0.2.0/fablo.sh -o /usr/local/bin/fablo && sudo chmod +x /usr/local/bin/fablo
fablo init node

Now, copy the files fabric-config.json (in HealthShare), index.js, package.json, package-lock.json (in HealthShare/chaincodes/chaincode-kv-node) and paste them into their respective areas inside your App directory and replace the existing files.
fablo-config.json contains the architecture (channels, organizations, chaincode arrays)
index.js bears the entirety of the chaincode logic

Finally, run the below command:
fablo up fablo-config.json

The network is set up, chaincodes packaged and installed, organizations and channels created.

For information on how to use Fablo, refer to https://github.com/hyperledger-labs/fablo
