import requests
import rsa
import json
from onions import InsecureRSABC, Certificate, Onion, CONST_KEYSERVER_URL, CONST_NODE_PORT

class OnionSender:
    def __init__(self):
        print("")

    def makeOnionFromMessage(dest, payload, cert):
        new_onion = Onion(dest, payload)
        Onion.wrap(new_onion, cert)
        return Onion.toString(new_onion)
        
    def makeCertFromResponseString(str):
        workingStr = str.split(", ")
        name = workingStr[1:-1]
        uname = workingStr[0][3:-1]
        testKey = rsa.PublicKey.load_pkcs1(workingStr[2][1:-3].replace(r'\n', "\n").encode(), format='PEM')
        return Certificate(name, uname, testKey)
    
    def makeOnionFromMessageAndRecipient(recipient, message):
        #get the recipient's public key from the key server
        keyResponse = requests.get(f"{CONST_KEYSERVER_URL}/KEYS?un={recipient}")

        #make a cert for the recipient's public key
        cert = OnionSender.makeCertFromResponseString(keyResponse.text)

        #make an onion for the recipient with a message and the cert
        return OnionSender.makeOnionFromMessage(recipient, message, cert)

        


    
def run(sender=OnionSender, port=CONST_NODE_PORT):
    #currently sends an onion one time
    #set the recipient
    recipient = input("Recipient:")
    message = input("Message:")
    string_onion = sender.makeOnionFromMessageAndRecipient(recipient, message)

    while True:
        old_recipient = recipient
        recipient = input("Recipient:")
        if recipient == "SEND":
            break

        string_onion = sender.makeOnionFromMessageAndRecipient(recipient, string_onion)

    destResponse = requests.get(f"{CONST_KEYSERVER_URL}/NODES?un={old_recipient}")
    ip = destResponse.text.split()[1][1:-2]

    #set the destination for the entire onion
    url = f"http://{ip}:{CONST_NODE_PORT}"

    #send the onion
    try:
        response = requests.post(url, string_onion)
    except:
        print("FAIL")

if __name__ == '__main__':
    run(port=CONST_NODE_PORT)
