import argparse
import requests
import json
from libs.smbconnection import SMBConnection
from libs.decrypter import RemoteOperations, NTDSHashes
from libs.utils import parse_target


def checkHashPart(username,hashPart,fullHash,target='necronomicon.patchrequest.com:8080'):
    data = {'username':username,'hash':hashPart}
    
    answer = requests.post("https://"+target,data=data)
    
    if answer.text != "null":
        possibleHashes = json.loads(answer.text)
        for hash in possibleHashes:
            if hash['hash'] == fullHash:
                print("[+] Username: " + username)
                print("[+] Hash: " + fullHash)
                print()
            
          
    
  


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
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

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
                                           pwdLastSet=True, resumeSession=None,
                                           outputFileName=None, justUser=None,
                                           printUserStatus= False)
    print("[+] Success\n")
    print("[-] Extracting Hashes")
    strings = NTDSHashes.dump()
    print("[+] Success! Hashcount: " + str(len(strings)) + "\n")
    if len(strings) > 0:

        print("[-] Processing hashes")
        print("\n")
        for string in strings:
            parts = string.split(':')
            username = parts[0]
            lmhash = parts[2]
            nthash = parts[3]
            lastSet = parts[6].split(" ")[1].strip()
            lastSet = lastSet.replace("(","").replace(")","").replace("pwdLastSet=","")

            
            nthashPart = nthash[-12:]
        
            checkHashPart(username,nthashPart,nthash,target='necronomicon.patchrequest.com')
        print("\n[+] Finished!")
    remoteOps.finish()
    NTDSHashes.finish()
    

