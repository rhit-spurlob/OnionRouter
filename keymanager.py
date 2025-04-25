#
# keymanager.py
#
# A utility to create and share keys in Pathetic Certificate form.
# This is useful for CSSE 490 - Data Privacy and Protection when doing the
# OnionRouter exercise.
#
# (c) 2024 Sid Stamm <stammsl@rose-hulman.edu>
# 

import json
import urllib.request
import urllib.parse

from onions import Certificate, CONST_KEYSERVER_URL

def postToServer(cert):
    """
    Sends the given certificate to the keyserver.
    NOTE: it double-checks that the cert is not a secret key certificate.

    @param cert: the certificate to send

    @returns the content of the server's response
    """
    if cert.isPrivate():
        print("ERROR: cannot send private certificate to key server!")
        return
    
    data = urllib.parse.quote(cert.asJSON())
    data = data.encode("ascii")
    try:
        with urllib.request.urlopen(f'{CONST_KEYSERVER_URL}/', data) as f:
            return f.read().decode('utf-8')
    except urllib.error.URLError as e:
        print("\n", e)
        return None


def downloadFromServer(fname):
    """
    Downloads a JSON list of certificates from the keyserver.
    """
    print(f'Downloading "{fname}"... ', end='')
    req = urllib.request.Request(f'{CONST_KEYSERVER_URL}/KEYS')
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.URLError as e:
        print("\n", e)
    else:
        with open(fname, 'w+') as f:
            f.write(response.read().decode('utf-8'))
        print("done.")


if __name__ == '__main__':
    print("Welcome to the key manager.")

    CMDS = ["new", "show", "import", "export", "send", "download", "exit"]

    cmd = input(f'What would you like to do ({CMDS})? ')
    pubcert = None
    seccert = None


    while(cmd != "exit"):
        if cmd == "new":
            n = input("What is your name? ")
            un = input("What is your RHIT username? ")
            pubcert, seccert = Certificate.MakePair(name=n, uname=un)
            print("Generation complete.  I recommend you 'export' to save your keypair!\n")

        elif cmd == "export":
            pubcert.writeToFile("pubcert.json")
            seccert.writeToFile("secretcert.json")
            print("Exported keypair to json files.")

        elif cmd == "import":
            pubcert = Certificate.FromFile("pubcert.json")
            seccert = Certificate.FromFile("secretcert.json")
            print("Imported keypair from json files.")

        elif cmd == "show":
            print(pubcert)
            print(seccert)

        elif cmd == "send":
            # IMPORTANT: DO NOT SEND THE SECRET CERT!
            res = postToServer(pubcert)
            if res is not None:
                print(res)

        elif cmd == "download":
            downloadFromServer("keys-downloaded.json")

        else:
            print(f'Unknown command, {cmd}. Please try again.')

        cmd = input(f'Now what? ({CMDS}) ')

    exit()

