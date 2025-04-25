#
# keyserver.py
#
# A utility to manage a small database of keys / certificates
# and then online nodes.
# This is useful for CSSE 490 - Data Privacy and Protection when doing the
# OnionRouter exercise.
#
# If data is posted to this server, it's expected to be a key to add/update
# If data is requested via GET, it is one of:
#  - a request for all the keys
#       -- /KEYS
#  - a request for a key given a username 
#       -- /KEYS?un=<uname>
#  - a request to get a node's status in the database (or all):
#       -- /NODES    <-- all nodes in a list
#       -- /NODES?un=<uname>
#  - a request to set a node's status in the database:
#       -- /ONLINE?un=<uname>
#       -- /OFFLINE?un=<uname>
#
# (c) 2024 Sid Stamm <stammsl@rose-hulman.edu>
# 

# for databasey stuff
import sqlite3

import json
import urllib.parse
from urllib.request import pathname2url

import onions

KEYDB = "keys.sqlite3"

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class KeyDatabase():

    DBFILE="keys.sqlite3"

    def __init__(self):
        try:
            dburl = pathname2url(KeyDatabase.DBFILE)
            dburi = f'file:{dburl}?mode=rw'
            self._con = sqlite3.connect(dburi, uri=True)
        except sqlite3.OperationalError:
            # DB did not exist, this will create it
            self._con = sqlite3.connect(KeyDatabase.DBFILE)
            self.InitializeDatabase()

    def Disconnect(self):
        self._con.close()

    def InitializeDatabase(self, soft=True):
        """If the database doesn't exist, creates the schema in the file.

        @param soft: if True, does not drop/overwrite tables if they exist.

        The certificates schema is simple:
            certs(uname, name, pubkey)
            'uname' is the username for the owner of the key (This is the PRIMARY KEY)
            'name' is a human-readable name
            'pubkey' is base64 encoded for integrity

        Connections are managed in the 'nodes' table:
            nodes(uname, ip, lastseen)
            'uname' is the username for the owner of the Node (so the right pubkey can be used)
                    (This is the PRIMARY KEY)
            'ip' is the IP address where the node is listening to HTTP
            'lastseen' is a timestamp updated when the node was last verified online
        """
        cur = self._con.cursor()
        if soft:
            cur.executescript("""
                BEGIN;
                CREATE TABLE if NOT EXISTS certs(uname PRIMARY KEY, name, pubkey);
                CREATE TABLE if NOT EXISTS nodes(uname PRIMARY KEY, ip, lastseen);
                COMMIT;
            """)
        else:
            cur.executescript("""
                BEGIN;
                CREATE TABLE certs(uname PRIMARY KEY, name, pubkey);
                CREATE TABLE nodes(uname PRIMARY KEY, ip, lastseen);
                COMMIT;
            """)

    def ClearNode(self, uname):
        cur = self._con.cursor()
        cur.execute("DELETE FROM nodes WHERE uname = ?", (uname,))
        self._con.commit()

    def SetNode(self, uname, ip):
        cur = self._con.cursor()
        cur.execute("INSERT OR REPLACE INTO nodes VALUES ( ?, ?, CURRENT_TIMESTAMP )", (uname, ip,))
        self._con.commit()

    def GetNodes(self, uname=None):
        cur = self._con.cursor()
        if uname is not None:
            cur.execute("SELECT * FROM nodes WHERE uname = ?", (uname,))
        else:
            cur.execute("SELECT * FROM nodes")
        return cur.fetchall()

    def SetCertWithFields(self, uname, name, key):
        cur = self._con.cursor()
        cur.execute("INSERT OR REPLACE INTO certs VALUES ( ?, ?, ? )", (uname, name, key))
        self._con.commit()

    def SetCert(self, cert : onions.Certificate):
        """Uses a Pathetic Certificate instance, and adds it to the DB.
        """
        self.SetCertWithFields(cert._uname, cert._name, cert.KeyAsPEM().decode('utf-8'))

    def GetCerts(self, uname=None):
        cur = self._con.cursor()
        if uname is not None:
            cur.execute("SELECT * FROM certs WHERE uname = ?", (uname,))
        else:
            cur.execute("SELECT * FROM certs")
        return cur.fetchall()



class OnionKeyServer(BaseHTTPRequestHandler):
    def _set_response(self, content_type='text/html', resp_code=200):
        self.send_response(resp_code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_GET(self):
        """GET requests have multiple endpoint options:
            - a request for all the keys
                 -- /KEYS
            - a request for a key given a username 
                 -- /KEYS?un=<uname>
            - a request to get a node's status in the database (or all):
                 -- /NODES    <-- all nodes in a list
                 -- /NODES?un=<uname>
            - a request to set a node's status in the database:
                 -- /ONLINE?un=<uname>
                 -- /OFFLINE?un=<uname>
        """
        #logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        logging.info("GET request,\nPath: %s\n", str(self.path))

        qs = urllib.parse.urlparse(self.path).query
        qs = urllib.parse.parse_qs(qs)

        # grab some query parameters just in case
        uname = qs['un'][0] if 'un' in qs else None

        if self.path == "/favicon.ico":
            self._set_response(content_type="image/x-icon")
            self.wfile.write(b'')

        elif self.path.startswith("/KEYS"):
            db = KeyDatabase()
            ks = db.GetCerts(uname=uname)
            db.Disconnect()
            self._set_response(content_type="application/json")
            self.wfile.write(json.dumps(ks).encode('utf-8'))

        elif self.path.startswith("/NODES"):
            db = KeyDatabase()
            ks = db.GetNodes(uname=uname)
            db.Disconnect()
            self._set_response(content_type="application/json")
            self.wfile.write(json.dumps(ks).encode('utf-8'))
        elif self.path.startswith("/ONLINE"):
            if uname is None:
                self._set_response(resp_code=500)
                self.wfile.write("Going online requires node ID (uname)".encode('utf-8'))
            else:
                db = KeyDatabase()
                ks = db.SetNode(uname=uname, ip=self.client_address[0])
                db.Disconnect()
                self._set_response()
                self.wfile.write("Node Online".encode('utf-8'))

        elif self.path.startswith("/OFFLINE"):
            if uname is None:
                self._set_response(resp_code=500)
                self.wfile.write("Going offline requires node ID (uname)".encode('utf-8'))
            else:
                db = KeyDatabase()
                ks = db.ClearNode(uname=uname)
                db.Disconnect()
                self._set_response()
                self.wfile.write("Node Removed".encode('utf-8'))

        else:
            self._set_response()
            self.wfile.write("Sorry, I don't respond to GET requests.".encode('utf-8'))

    def do_POST(self):
        """ When a post comes in, look for a key/cert and then either update the
        db or add it.
        """
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("POST request received,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        try:
            msg = urllib.parse.unquote(post_data.decode('utf-8'))

            # Expecting this to be a JSON blob
            cert = onions.Certificate.FromJSON(msg)

            # Enter the cert into the database
            db = KeyDatabase()
            db.SetCert(cert)
            db.Disconnect()

            self._set_response()
            self.wfile.write("Thanks for the message.  :)".encode('utf-8'))
            print(msg)

        except Exception as e:
            self.send_response(500)
            print("ERROR decoding POST: ", e)

def run(server_class=HTTPServer, handler_class=OnionKeyServer, port=onions.CONST_KEYSERVER_PORT):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting RHIT Onion KEYSERVER...\n')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    logging.info('Stopping RHIT Onion KEYSERVER...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run(port=onions.CONST_KEYSERVER_PORT)