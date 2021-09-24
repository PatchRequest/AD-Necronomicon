import argparse
from libs.smbconnection import SMBConnection
from libs.decrypter import RemoteOperations, NTDSHashes
from libs.utils import parse_target




#py.exe .\main.py target=mylab.local/syncer:Abcdefghij1!@192.168.2.156


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help = True, description = "Lets take a little peak into the Necronomicon and look if we can find your Active Directory users in it")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    exec_method = "smbexec"
    args = parser.parse_args()
    domain, username, password, remoteName = parse_target(args.target)
    remoteHost = remoteName

    smbConnection = SMBConnection(remoteName, remoteHost)
    nthash = ""
    lmhash = ""
    smbConnection.login(username, password, domain, lmhash, nthash)
    remoteOps  = RemoteOperations(smbConnection, False, remoteHost)
    remoteOps.setExecMethod(exec_method)
    #NTDSFileName = remoteOps.saveNTDS()
    NTDSFileName = None
    bootKey = None
    NTDSHashes = NTDSHashes(NTDSFileName, bootKey, True, history=False,
                                           noLMHash=True, remoteOps=remoteOps,
                                           useVSSMethod=False, justNTLM=True,
                                           pwdLastSet=True, resumeSession=None,
                                           outputFileName=None, justUser=None,
                                           printUserStatus= False)
    
    strings = NTDSHashes.dump()

    print("\n\n")
    for string in strings:
        parts = string.split(':')
        username = parts[0]
        lmhash = parts[2]
        nthash = parts[3]
        lastSet = parts[6].split(" ")[1].strip()
        lastSet = lastSet.replace("(","").replace(")","").replace("pwdLastSet=","")
        print(username + "   " + nthash + "    " +lastSet)
    print("\n\n")
    remoteOps.finish()
    NTDSHashes.finish()
    

