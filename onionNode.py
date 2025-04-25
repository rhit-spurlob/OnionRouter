#
# onionNode.py
#
# A program that acts as a node in a sad little onion router project.
# It listens on port 10101 for incoming HTTP requests, expecting an onion message.
#
# Upon receiving an onion message, it "peels" the onion and sends it to the next
# destination -- assumming it is online.
#   - If there is no next destination, it prints the payload and closes the connection.
#   - If the next hop is online, it forwards the payload of the peeled onion.
#   - If the next hop is not online, it responds to the origin with an error.
#
# This is useful for CSSE 490 - Data Privacy and Protection
# when doing the OnionRouter exercise.
#
# (c) 2024 Sid Stamm <stammsl@rose-hulman.edu>
# 

import json
import urllib.parse
import requests

from onions import Certificate, Onion, CONST_KEYSERVER_URL, CONST_NODE_PORT

KEYFILE = "keys-downloaded.json"

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class OnionNodeHandler(BaseHTTPRequestHandler):
    """This class is used to handle incoming HTTP requests.  Specifically,
    those requests will be from other OnionNodes to peel and forward an onion,
    or they might be destined for this node (a final message).
    """

    def _set_response(self):
        """Helper to prepare a response.
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("Sorry, I don't respond to GET requests.".encode('utf-8'))

    def do_POST(self):
        """Here's where the magic happens:
        When a post comes in, look for an Onion message and then either display
        it or forward it on.
        """
        content_length = int(self.headers['Content-Length']) # Need this to do the next step
        post_data = self.rfile.read(content_length)          # grab the data from the POST
        # print("------------------ Post Data ----------------\n")
        # print(post_data)

        # NOTE: You can use this logging tool to see what came in.
        print("------------------ Log ----------------\n")
        logging.info("POST request received,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
               str(self.path), str(self.headers), post_data.decode('utf-8'))
        
        try:
            # Because the incoming message was quoted, must unquote it first.
            msg = urllib.parse.unquote(post_data.decode('utf-8'))

            # print("------------------ Message ----------------\n")
            # print(msg)

            # print("------------------ Onion Check ----------------\n")
            # print(Onion.isOnion(msg))

            if Onion.isOnion(msg):
                # TODO: load my secret key so I can use it to peel the onion
                priv = Certificate.FromFile("secretcert.json")
                
                #Make the onion from the message
                new_onion = Onion.FromString(msg)

                # TODO: is this onion message for me?
                if not Onion.isFor(new_onion, priv): 
                    raise Exception("Wrong recipient")
                # If not, this is an error!
                
                # TODO: peel it.  Be sure to report any errors to the sender.
                peeled_onion = Onion.peel(new_onion, priv)
                print(peeled_onion)

                # TODO: is the payload a message or an onion?
                # If the peeled onion contains a message, print it out and then be done.
                if not Onion.isOnion(peeled_onion):
                    print(peeled_onion)
                else:
                    peeled_onion = Onion.FromString(peeled_onion)
                    destResponse = requests.get(f"{CONST_KEYSERVER_URL}/NODES?un={peeled_onion._dest}")
                    ip = destResponse.text.split()[1][1:-2]

                    #set the destination for the entire onion
                    url = f"http://{ip}:{CONST_NODE_PORT}"

                    #send the onion
                    try:
                        response = requests.post(url, Onion.toString(peeled_onion))
                    except:
                        print("FAIL")


                # If we found another onion, forward to next hop!
                # TODO: Find out how to forward
                # - look up the next hop IP address by username (keyserver)
                # - try connecting to that OnionNode
                # - If it's online, forward the inner onion on to the next node

                self._set_response()
                self.wfile.write("Thanks for the onion.  :)".encode('utf-8'))
            else:
                # Is not an onion.  Thank the sender and print it out.
                self._set_response()
                self.wfile.write("Thanks for the message.  :)".encode('utf-8'))
                print(msg)

        except Exception as e:
            self.send_response(500)
            print("ERROR decoding POST: ", e)

def run(server_class=HTTPServer, handler_class=OnionNodeHandler, port=CONST_NODE_PORT):
    pub = Certificate.FromFile("pubcert.json")
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    response = requests.get(f"{CONST_KEYSERVER_URL}/ONLINE?un={pub._uname}")
    logging.info('Starting RHIT Onion Node...\n')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    response = requests.get(f"{CONST_KEYSERVER_URL}/OFFLINE?un={pub._uname}")
    httpd.server_close()
    logging.info('Stopping RHIT Onion Node...\n')

if __name__ == '__main__':
    run(port=CONST_NODE_PORT)