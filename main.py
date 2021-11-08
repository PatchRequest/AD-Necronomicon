
import argparse
import os
from libs.smbconnection import SMBConnection
from libs.decrypter import RemoteOperations, NTDSHashes
from libs.utils import parse_target



    

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
    parser.add_argument('--key',  help='The API-Key for the Backend', required=False)
    parser.add_argument('--speed',  help='The speed of the queries to the backend [slow,fast]\nslow: Partial hashes are send to the backend -> Slow search in the db \nfast: Full hash is send to backend -> faster search in db', required=False,default="fast")
    parser.add_argument('--backend',  help='Address of a custom Backend. Just use it if you know what you are doing!', required=False,default="necronomicon.patchrequest.com")
    parser.add_argument('--offline',  help='Using the offlinemode which does not use a backend. \n !!! It will download 20GB and use a local hash comparison !!!', required=False,action="store_true")
    parser.add_argument('--nossl',  help='Using the offlinemode which does not use a backend. \n !!! It will download 20GB and use a local hash comparison !!!', required=False,action="store_true")



    exec_method = "smbexec"
    print("[*] Parsing arguments\n")
    args = parser.parse_args()

    key = args.key
    sslUse = not args.nossl
    offline =  args.offline
    backend = args.backend
    speed = args.speed

    domain, username, password, remoteName = parse_target(args.target)

    if offline:
        print("[+] Offlinemode")
    print("[+] Domain: " + domain)
    print("[+] Username: " + username)
    print("[+] password: " + "*"*len(password))
    print("[+] Target: " + remoteName)
    if key != None:
        print("[+] Key: " + key)
    print("[+] Using SSL: " + ("Yes" if sslUse else "No"))
    print("[+] Backend: " + backend)
    print("[+] Mode: " + speed)
    print()
    remoteHost = remoteName

    print("[*] Starting SMB Connectiont to " + remoteName)
    smbConnection = SMBConnection(remoteName, remoteHost)
    print("[+] Connection succesfull\n")
    nthash = ""
    lmhash = ""
    print("[*] Logging in with user " + username)
    smbConnection.login(username, password, domain, lmhash, nthash)
    print("[+] Login succesfull\n")
    remoteOps  = RemoteOperations(smbConnection, False, remoteHost)
    remoteOps.setExecMethod(exec_method)
      
    NTDSFileName = None
    bootKey = None
    print("[*] Getting NTDS File")
    NTDSHashes = NTDSHashes(NTDSFileName, bootKey, True, history=False,
                                           noLMHash=True, remoteOps=remoteOps,
                                           useVSSMethod=False, justNTLM=True,
                                           pwdLastSet=False, resumeSession=None,
                                           outputFileName=None, justUser=None,
                                           printUserStatus= False)
    print("[+] Success\n")
    print("[*] Extracting Hashes")
    strings = NTDSHashes.dump()
    print("[+] Success! Hashcount: " + str(len(strings)) + "\n")
    if len(strings) > 0:

        print("[*] Writing Hashes to File")
        print("\n")
        
        if offline:
            # Offline + fast
            with open('./checker/ntds.dat', 'w') as f:
                for string in strings: 
                    parts = string.split(':')
                    username = parts[0]
                    lmhash = parts[2]
                    nthash = parts[3]
                    f.write(username + "-.-" + nthash+"\n")
                f.close()
            print("[*] Starting second Stage\n")
            os.chdir("checker")
            os.system("Main.exe ntds.dat hashlist")
        else:
            if speed == "slow":
                # Online + slow
                with open('./checker/ntds.dat', 'w') as f: 
                    for string in strings:
                        parts = string.split(':')
                        username = parts[0]
                        lmhash = parts[2]
                        nthash = parts[3]
                        nthashPart = nthash[0:15]
                        f.write(username + "-.-" + nthashPart+"\n")
                    f.close()
            else:
                # Online + fast
                with open('./checker/ntds.dat', 'w') as f: 
                    for string in strings:
                        parts = string.split(':')
                        username = parts[0]
                        lmhash = parts[2]
                        nthash = parts[3]
                        f.write(username + "-.-" + nthash+"\n")
                    f.close()

        print("\n[+] Finished!")
    remoteOps.finish()
    NTDSHashes.finish()
    

"""
        
            for string in strings:
                print(string)
                parts = string.split(':')
                username = parts[0]
                lmhash = parts[2]
                nthash = parts[3] 

                print(username)
                print(nthash+"\n")

                if args.speed == "slow":
                    nthashPart = nthash[0:15]
                    checkHashPart(username,nthashPart,nthash,speed=speed,key=key,backend=backend,ssl=sslUse)
                else:
                    checkHashPart(username,nthash,nthash,key=key,backend=backend,ssl=sslUse)


def checkHashPart(username,hashPart,fullHash,backend='necronomicon.patchrequest.com',speed="fast",key="",ssl=True):
    data = {'username':username,'hash':hashPart,'speed':speed,'key':key}

    if ssl:
        answer = requests.post("https://"+backend,data=data,timeout=10)
    else:
        answer = requests.post("http://"+backend,data=data,timeout=10)

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
          

"""