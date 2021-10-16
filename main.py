import argparse
import requests
import json
from libs.smbconnection import SMBConnection
from libs.decrypter import RemoteOperations, NTDSHashes
from libs.utils import parse_target


def checkHashPart(username,hashPart,fullHash,target='necronomicon.patchrequest.com',speed="fast",key=""):
    data = {'username':username,'hash':hashPart,'speed':speed,'key':key}
    answer = requests.post("https://"+target,data=data)
    if answer.text != "null":
        if answer.status_code == 200:
            possibleHashes = json.loads(answer.text)
            for hash in possibleHashes:
                if hash['hash'] == fullHash:
                    print("[+] Username: " + username)
                    print("[+] Hash: " + fullHash)
                    print()
        else:
            print(answer.text)
          
    
  


if __name__ == "__main__":
    symbol = """
 █████╗ ██████╗     ███╗   ██╗███████╗ ██████╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███╗   ███╗██╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗    ████╗  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗████╗ ████║██║██╔════╝██╔═══██╗████╗  ██║
███████║██║  ██║    ██╔██╗ ██║█████╗  ██║     ██████╔╝██║   ██║██╔██╗ ██║██║   ██║██╔████╔██║██║██║     ██║   ██║██╔██╗ ██║
██╔══██║██║  ██║    ██║╚██╗██║██╔══╝  ██║     ██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║╚██╔╝██║██║██║     ██║   ██║██║╚██╗██║
██║  ██║██████╔╝    ██║ ╚████║███████╗╚██████╗██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                                                                                                                          
    """

    print(symbol)

    parser = argparse.ArgumentParser(add_help = True, description = "Lets take a little peak into the Necronomicon and look if we can find your Active Directory users in it")
    parser.add_argument('target',  help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('key',  help='The API-Key for the Backend')
    parser.add_argument('--speed',  help='The speed of the queries to the backend [slow,fast]\nslow: Partial hashes are send to the backend -> Slow search in the db \nfast: Full hash is send to backend -> faster search in db', required=False,default="fast")

    exec_method = "smbexec"
    print("[-] Parsing arguments\n")
    args = parser.parse_args()

    domain, username, password, remoteName = parse_target(args.target)
    print("[+] Domain: " + domain)
    print("[+] Username: " + username)
    print("[+] password: " + "*"*len(password))
    print("[+] Target: " + remoteName)
    print()
    remoteHost = remoteName

    print("[-] Starting SMB Connectiont to " + remoteName)
    smbConnection = SMBConnection(remoteName, remoteHost)
    print("[+] Connection succesfull\n")
    nthash = ""
    lmhash = ""
    print("[-] Logging in with user " + username)
    smbConnection.login(username, password, domain, lmhash, nthash)
    print("[+] Login succesfull\n")
    remoteOps  = RemoteOperations(smbConnection, False, remoteHost)
    remoteOps.setExecMethod(exec_method)
      
    NTDSFileName = None
    bootKey = None
    print("[-] Getting NTDS File")
    NTDSHashes = NTDSHashes(NTDSFileName, bootKey, True, history=False,
                                           noLMHash=True, remoteOps=remoteOps,
                                           useVSSMethod=False, justNTLM=True,
                                           pwdLastSet=False, resumeSession=None,
                                           outputFileName=None, justUser=None,
                                           printUserStatus= False)
    print("[+] Success\n")
    print("[-] Extracting Hashes")
    strings = NTDSHashes.dump()
    print("[+] Success! Hashcount: " + str(len(strings)) + "\n")
    if len(strings) > 0:

        print("[-] Processing hashes")
        print("\n")
        key = args.key.split("=")[1]
        for string in strings:
            parts = string.split(':')
            username = parts[0]
            lmhash = parts[2]
            nthash = parts[3]
            if args.speed == "slow":
                nthashPart = nthash[0:15]
                checkHashPart(username,nthashPart,nthash,speed=args.speed,key=key)
            else:
                checkHashPart(username,nthash,nthash,key=key)



        print("\n[+] Finished!")
    remoteOps.finish()
    NTDSHashes.finish()
    

