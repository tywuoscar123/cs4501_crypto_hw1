from calendar import c
from datetime import datetime
from encodings import utf_8
import hashlib
import sys
import binascii
from xml.sax.handler import feature_external_ges
import rsa
import os

#python3 cmoney.py
#define name of currency
currencyName = "FreeCoinz"

#print name of currency
def name():
    print(currencyName)
    return




#generate genesis block with phrase
def genesis():
    quote = "Revolution of our times."
    f = open("block_0.txt", "w")
    f.write(quote)
    print("Genesis block created in 'block_0.txt'")
    return




#generate wallet with keys in text
def generate(fileName):
    (pubkey, privkey) = rsa.newkeys(1024)
    saveWallet(pubkey, privkey, fileName)
    signature = getWalletAddr(fileName)
    print("New wallet generated in '" + fileName + "' with signature " + signature)
    return




def address(fileName):
    print(str(getWalletAddr(fileName)))
    return




def fund(destAddr, amount, fileName):
    f = open(fileName, "w")
    fundSource = "From: free_money\n"
    fundDest = "To: " + destAddr + "\n"
    fundAmount = "Amount: " + amount + "\n"
    fundDate = "Date: " + str(datetime.now()) + "\n"
    f.writelines([fundSource, fundDest, fundAmount, fundDate])
    print("Funded wallet " + destAddr + " with " + amount + " " + currencyName + " on " + str(datetime.now()))
    return




def transfer(srcFileName, destAddr, amount, fileName):
    f = open(fileName, "w")
    srcAddr = str(getWalletAddr(srcFileName))
    transSrc = "From: " + srcAddr + "\n"
    transDest = "To: " + destAddr + "\n"
    transAmount = "Amount: " + amount + "\n"
    transDate = "Date: " + str(datetime.now()) + "\n"
    transactionInfo = transSrc + transDest + transAmount + transDate
    transSign = str(binascii.hexlify(getTransSign(loadWallet(srcFileName)[1], transactionInfo)).decode("utf-8"))
    f.writelines([transactionInfo, "\n", transSign])
    #Transferred 12.5 from alice.wallet.txt to d96b71971fbeec39 and the statement to '03-alice-to-bob.txt' on Tue Apr 02 23:09:00 EDT 2019
    print("Transferred " + amount + " from '" + srcFileName + "' to " + destAddr + " and the statement to '" + fileName + "' on " + str(datetime.now()) )
    return




#print out balance obtained from getBalance()
def balance(walletAddr):
    print(str(getBalance(walletAddr)))
    return




def verify(srcFileName, transFileName):
    f = open(transFileName)
    content = f.readlines()
    #need to add check for format?
    #case 1, funds
    if(content[0].split(" ")[1] == "free_money\n"):
        senderAddr = str(content[0].split(" ")[1][:-1])
        recepientAddr = content[1].split(" ")[1][:-1]
        amount = str(content[2].split(" ")[1][:-1])
        date = content[3].split(" ")[1] + content[3].split(" ")[2][:-1]
        transactionRecord = "free_money" + " transferred " + amount + " to " + recepientAddr + " on " + date  + "\n"
        with open("ledger.txt", "a+") as ledger:
            ledger.write(transactionRecord)
        print("Any funding request (i.e., from free_money) is considered valid; written to the ledger")
        return
    #case 2, transfer
    else:
        #binascii.hexlify(getTransSign(loadWallet(srcFileName)[1], transactionInfo)).decode("utf-8")
        #get data
        hash = content[5].encode("utf-8")
        hash = binascii.unhexlify(hash)
        pubKey = loadWallet(srcFileName)[0]
        record = "".join(content[0:4])
        amountFloat = float(content[2].split(" ")[1][:-1])
        senderAddr = str(content[0].split(" ")[1][:-1])
        #verify with public key and check balance at the same time
        if(rsa.verify(record.encode(),hash, pubKey) == "SHA-256" and getBalance(senderAddr) > amountFloat):
            with open("ledger.txt", "a+") as ledger:
                #a3e47443b0f3bc76 transferred 12.5 to 48adadf4fb921fca on 2022-02-07 02:38:31.012025 
                #extract data from ledger and write to file     
                recepientAddr = content[1].split(" ")[1][:-1]
                amount = str(amountFloat)
                date = content[3].split(" ")[1] + content[3].split(" ")[2][:-1]
                transactionRecord = senderAddr + " transferred " + amount + " to " + recepientAddr + " on " + date  + "\n"
                ledger.write(transactionRecord)
                #The transaction in file '04-bob-to-alice.txt' with wallet 'bob.wallet.txt' is valid, and was written to the ledger
                print("The transaction in file '" + transFileName + "' with wallet '" + srcFileName + " is valid, and was written to the ledger")
                return
        else:
            print(srcFileName + " has insufficient balance, transaction is invalid.")
    return




def mine(difficulty):
    currentPath = os.path.abspath(os.getcwd())
    blocks = []
    #get all name of the blocks in an array first
    for fileName in os.listdir(currentPath):
        if("block_" in fileName):
            blocks.append(fileName)
    previousHash = hashFile("block_" + str(len(blocks) - 1) + ".txt")
    #open both files and get hash from contents
    with open("ledger.txt", "r+") as ledgerFile, open("block_" + str(len(blocks)) + ".txt", "w+") as newBlock:
        newBlock.write(previousHash + "\n\n")
        for line in ledgerFile:
            newBlock.write(line)
        newBlock.seek(0,0)
        blockContent = newBlock.readlines()
        blockContent = "".join(blockContent).encode("utf-8")
        newBlockHash = hashlib.sha256(blockContent).hexdigest()
        nonce = 0
        mineSuccess = False
        #use while loop to find nonce
        while(mineSuccess != True):
            newSrc = newBlockHash + str(nonce)
            nonceHash =  hashlib.sha256(newSrc.encode("utf-8")).hexdigest()
            nonceHash = list(nonceHash)
            mineSuccess = all(num == "0" for num in nonceHash[:int(difficulty)])
            nonce += 1
        newBlock.seek(0,2)
        newBlock.write("\nNonce:" + str(nonce))
        #clear ledger
        ledgerFile.truncate(0)
    #Ledger transactions moved to block_1.txt and mined with difficulty 2 and nonce 1029
    print("Ledger transactions moved to block_" + str(len(blocks)) + ".txt and mined with difficulty " + difficulty + " and nonce " + str(nonce))
    return




def validate():
    #get number of blocks
    numBlocks = 0
    currentPath = os.path.abspath(os.getcwd())
    for fileName in os.listdir(currentPath):
        if("block_" in fileName):
            numBlocks += 1
    i = 1
    #start loop through every blk
    while(i < numBlocks):
        with open("block_" + str(i) + ".txt", "r") as currentBlock:
            savedHash = currentBlock.readline()
            prevHash = hashFile("block_" + str(i-1) + ".txt") + "\n"
            if(savedHash != prevHash):
                print("False")
                return
            i+=1
    print("True")
    return




#helper functions




#get addr of wallet from first 16 characters of pubkey hash
def getWalletAddr(fileName):
    signature = hashPubKey(fileName)[0:15]
    return signature




# gets the hash of a file; from https://stackoverflow.com/a/44873382
def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()




#generate hash of public key, save as first to hash
def hashPubKey(fileName):
    pubKey = loadWallet(fileName)[0]
    pubKey = pubKey.save_pkcs1(format='PEM')
    h = hashlib.sha256()
    h.update(pubKey)
    return h.hexdigest()




# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)




# given a hex reprensetation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)




# Load the wallet keys from a filename
def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey




# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return




#gets signature of transaction using private key of wallet
def getTransSign(privKey, input):
    signature = rsa.sign(input.encode(), privKey, "SHA-256")
    return signature

#get balance , needed for verifiy() and balance()
def getBalance(walletAddr):
    balance = 0
    currentPath = os.path.abspath(os.getcwd())
    #iterate through current dir to find ledger and block 
    for file in os.listdir(currentPath):
        if "ledger.txt" in file:
            ledger = open(file)
            records = ledger.readlines()
            for line in records:
                content = line.split(" ")
                #a3e47443b0f3bc76 transferred 12.5 to 48adadf4fb921fca on Tue Apr 02 23:09:14 EDT 2019
                #wallet transferred funds to another wallet, - balance (need to check transfer to self?)
                if content[0] == walletAddr and content[4] != walletAddr:
                    balance -= float(content[2])   
                #received money, + balance
                elif content[4] == walletAddr and content[0] != walletAddr:
                    balance += float(content[2])
        elif (file.find("block_") != -1 and file.find("block_0") == -1):
            block = open(file)
            records = block.readlines()[2:-1]
            for line in records:
                content = line.split(" ")
                #wallet transferred funds to another wallet, - balance (need to check transfer to self?)
                if content[0] == walletAddr and content[4] != walletAddr:
                    balance -= float(content[2])   
                #received money, + balance
                elif content[4] == walletAddr and content[0] != walletAddr:
                    balance += float(content[2])
    return float(balance)

if __name__ == "__main__":
    args = sys.argv
    # args[0] = current file
    # args[1] = function name
    # args[2:] = function args : (*unpacked)
    globals()[args[1]](*args[2:])