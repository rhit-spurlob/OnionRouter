#
# onions.py
#
# Contains classes to help with the Onion Router project in
# Rose-Hulman's "Data Privacy and Protection" class.
# 
# InsecureRSABC:
# A class that contains a couple somewhat insecure block cipher RSA subroutines
# that increase the usability of RSA keys for encryption/decryption of payloads.
# This is horribly vulnerable for large enciphered strings, but sufficient to 
# demonstrate how to encrypt/decrypt.
#
# Certificate:
# A class to model RSA certificates that bind a name and username to a key.
# Supports both public and private keys.  Sometimes called "Pathetic Certificate".
#
# Onion:
# A class to model wrapped/encrypted messages.  Onions can contain onions and
# always contain a pair of {destination, message}.
# 
# (c) 2024 Sid Stamm <stammsl@rose-hulman.edu>
#

import rsa
import base64
import json 

# Useful globals identifying where the keyserver lives.  (You might have to change this).
CONST_KEYSERVER_URL = "http://box.rose-hulman.edu:5555"
CONST_KEYSERVER_PORT = 5555

# The port used by Onion Nodes.  DON'T CHANGE THIS: USE THIS PORT
CONST_NODE_PORT = 10101

# Some specific header/trailer text to help identify ONION messages.
# See comments below for what an ONION looks like.  Note that the angle
# brackets <> indicate a "variable" or field value, and are not included
# in the actual ONION.

CONST_ONION_HEADER  = "--------------- ONION MESSAGE: ---------------\n"
#                      TO: <uname>\n
#                      <base64 encoded message, maybe many lines >\n
#                      < ... which could be another onion ...    >\n
CONST_ONION_TRAILER = "-------------- END ONION MESSAGE -------------\n"


class InsecureRSABC:
    """This class contains a couple somewhat insecure block cipher RSA subroutines
    that increase the usability of RSA keys for encryption/decryption of payloads.
    This is horribly vulnerable for large enciphered strings, but sufficient to 
    demonstrate how to encrypt/decrypt.

    THIS IS NOT CRYPTOGRAPHICALLY SECURE!
   
    Don't use RSA as a block cipher, it's very attackable.  We're only doing it
    here because this is a toy and is easy to do/explain.

    Sample usage:
    encrypts a message, then decrypts it.
    ASSUMES: you made a keypair already, and exported it from the keymanager

    >     # import the keys
    >     seccert = Certificate.FromFile("secretcert.json")
    >     pubcert = Certificate.FromFile("pubcert.json")
    > 
    >     ct = encrypt_payload("This is a secret message!", pubcert._key)
    >     print("Ciphertext = ", ct)
    >     pt = decrypt_payload(ct, seccert._key)
    >     print("Plaintext = ", pt)
    """

    def encrypt_payload(msg, public_key): 
        """Encrypt an RSA ciphertext given a key.
        This function assumes the key is tiny and encrypts blocks of five byte segments.

        @param msg: a str message
        @public_key: an RSA public key object
        @return an encrypted message in base64 (as ASCII)
        """
        seg_size = 2 # chunk size (max is 5 for tiny keys like default config)

        # encode into byte array
        msg = msg.encode('utf-8')

        # split into seg_size substrings
        chunks = [msg[i:i+seg_size] for i in range(0, len(msg), seg_size)]

        # encrypt each substring
        enc_chunks = [rsa.encrypt(c, public_key) for c in chunks]

        # stick the substrings together
        enc_bytes = b''.join(list(enc_chunks))

        # return the bytes encoded with base64
        return base64.encodebytes(enc_bytes).decode('ascii')
        

    def decrypt_payload(ciphertext, private_key):
        """Decrypt an RSA ciphertext given a key.
        This function assumes the message was segmented a certain way and encrypted in a block cipher.
        It also assumes the message was base64-encoded.

        @param ciphertext: an encrypted message
        @public_key: an RSA private key object
        @return a decrypted message as str
        """
        seg_size = 16 # chunk size (based on key - 16 in default config)

        # decode the message from base64
        ciphertext = base64.decodebytes(ciphertext.encode('ascii'))

        # split into encrypted blocks of seg_size length
        chunks = [ciphertext[i:i+seg_size] for i in range(0, len(ciphertext), seg_size)]

        # decrypt each block
        dec_chunks = [rsa.decrypt(c, private_key) for c in chunks]

        # reassemble the decrypted blocks and return the message
        return (b''.join(list(dec_chunks))).decode("utf-8")



class Onion:
    """ A class to model an "onion" object.
    Such an object contains a destination and payload.
    The destination is simply a username.
    The payload is a Base64-encoded string, which could be another onion.
    """
    def __init__(self, dest, payload):
        self._dest = dest
        self._payload = payload
    
    def toString(self):
        return CONST_ONION_HEADER + "TO: " + self._dest + "\n" + self._payload + CONST_ONION_TRAILER

    def FromString(onionstr):
        """Attempts to parse out a string into an object representation of an onion.
        Yeah, this is a factory.
        """
        try:
            m = onionstr.split(CONST_ONION_HEADER, 1)[1]
            m = m.split(CONST_ONION_TRAILER,1)[0]

            while len(m.strip()) > 0:
                # Grab the first line, and see if it is the "TO" line...
                dest, m = m.split("\n", 1)
                if dest.strip().startswith("TO:"):
                    dest = dest[3:].strip()
                    m = m.strip()
                    break
            if len(dest) < 1:
                print("ERROR parsing onion: no 'TO' field.")
                return None

            return Onion(dest, m)

        except Exception as e:
            print("ERROR parsing onion:", e)
            return None


    def isOnion(s):
        """A class method that attempts parsing 's' as if it was an onion message.

        @param s: the string to check.  The expected format of 's' is:
                    --------------- ONION MESSAGE: ---------------\n
                    TO: <username>\n
                    <base64 encoded message>\n
                    -------------- END ONION MESSAGE -------------\n
                    <optional extra text that gets ignored.>

        @returns True if the format is ok, and False otherwise.
        """
        return s.startswith(CONST_ONION_HEADER) and "TO:" in s and CONST_ONION_TRAILER in s

    def isFor(self, secret_cert):
        """Given a secret cert, determines if this onion object can be peeled.
        """
        return secret_cert.isPrivate() and secret_cert.isFor(self._dest)

    def peel(self, secret_cert):
        if(not self.isFor(secret_cert)):
            print("Error: cannot peel onion with the provided certificate -- wrong subject.")
            return None

        # decrypt the payload and produce an inner onion if there is one.
        try:
            # Cannot use raw rsa.decrypt here for large payloads
            #message = rsa.decrypt(self._payload, secret_cert._key)
            message = InsecureRSABC.decrypt_payload(self._payload, secret_cert._key)
            # if Onion.isOnion(message):
            #     return Onion.FromString(message)
            # else:
            return message
        except rsa.DecryptionError as e:
            print("Error peeling the onion: ", e)

    def wrap(self, public_cert):
        try:
            self._payload = InsecureRSABC.encrypt_payload(self._payload, public_cert._key) 
        except rsa.DecryptionError as e:
            print("Error wrapping onion: ", e)


class Certificate:
    def __init__(self, name, uname, rsakey):
        self._name = name
        self._uname = uname
        self._key = rsakey

    def MakePair(name, uname, key_size=127):
        pubkey, seckey = rsa.newkeys(key_size)
        p = Certificate(name, uname, pubkey)
        s = Certificate(name, uname, seckey)
        return p, s

    def isFor(self, subject):
        return self._uname == subject or self._name == subject

    def isPublic(self):
        return isinstance(self._key, rsa.PublicKey)

    def isPrivate(self):
        return isinstance(self._key, rsa.PrivateKey)

    def asJSON(self):
        """Converts this cert to JSON representation.
        """
        d = {
              "ctype": "PRIVATE" if self.isPrivate() else "PUBLIC",
              "name": self._name,
              "username": self._uname,
              "key": self.KeyAsPEM().decode("utf-8")
        }
        return json.dumps(d)

    def FromJSON(blob):
        """Converts a JSON serialized representation of this cert into an object.
        Should be the inverse of Onion.asJSON()
        """
        d = json.loads(blob)
        k = d["key"]

        if d['ctype'] == "PRIVATE": k = rsa.PrivateKey.load_pkcs1(k, format='PEM')
        else:                       k = rsa.PublicKey.load_pkcs1(k, format='PEM')

        return Certificate(name=d["name"],
                           uname=d["username"],
                           rsakey=k)


    def writeToFile(self, fname):
        """Writes the contents of this cert to a file.
        @param fname: the filename to write
        @return Nothing
        """
        if self.isPrivate(): print(f'WARNING: writing private key to file {fname}')
        with open(fname, 'w+') as f:
            f.write(self.asJSON())

    def FromFile(fname):
        """Reads this certificate information from a file.
        @param fname: the filename to read
        @return an instance of Certificate (or None)
        """
        with open(fname, 'r+') as f:
            s = f.read()
        return Certificate.FromJSON(s)

    def KeyAsPEM(self):
        """Returns the key in PEM format.
        This format includes key header/trailer and is base64 encoded.
        """
        if isinstance(self._key, rsa.PrivateKey):
            return rsa.PrivateKey.save_pkcs1(self._key, format='PEM')
        else:
            return rsa.PublicKey.save_pkcs1(self._key, format='PEM')

    def __str__(self):
        serkey = None
        keytype = "Public"
        keytype = "Public" if isinstance(self._key, rsa.PublicKey) else "Private"
        serkey = self.KeyAsPEM()
        # prune off trailing newlines and header/trailer.
        serkey = b'\n'.join(serkey.split(b'\n')[1:-2])
        s = f'''{{  Certificate ({keytype} KEY):
  Name:     "{self._name}",
  Username: "{self._uname}",
  Key:      "{serkey}"
}}'''
        return s
