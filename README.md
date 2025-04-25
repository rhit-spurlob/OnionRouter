# Onion Router Exercise
*This is a template for Rose-Hulman Institute of Technology* <br/>
*CSSE 490 - Data Privacy & Protection*

This is starter code for an onion router exercise.

## Expectations
You will work in your project team to create a tiny onion "router" (messaging) system (Phases 1-6).

After your project team has completed the onion router, we will combine all the teams to make a BIGGER network!

You are expected to work in pairs or as a small team together on writing code.  Everyone on your team is expected to understand the result, and you all should contribute a little something to your github repository (a fork of mine).

### Here's a summary of the phases:
1. Inspection and understanding the `keymanager`
2. Inspection of and using the `keyserver`
3. Making keys and sending them to the `keyserver`
4. Sending messages and encrypting single-layered onions.
5. Sending messages using multiple-layered onions
6. Building a random path and an onion to traverse that path.
7. (Together in Class) Sending large-group onion messages.


### Overview of the major pieces in this project
The onion "routing" system (okay, it's just a onion message passing anonymizer) contains the following components:
* `onions.py` - a python module that contains library routines for creating keypairs, 'onion' messages, and for communicating with the keyserver.  All the other programs import from this library.
* `keyserver.py` - a server used for discovering nodes and keys.  It is used by all of the other components to find information about the network.  This server is already created for you and  maintains a database of:
    - public key and userid mappings
    - IP address and userid mappings
* `keymanager.py` - a command-line tool to create keypairs and save them to files or send them to the keyserver.
* `onionNode.py` - a node of the onion network that knows how to "peel" a layer off an onion (decrypt a layer) and then pass it onto the next node in a circuit.  This tool also displays messages for which it is the final destination.
* `onionSender.py` - a command-line tool you will create to create a random onion "circuit", wrap an onion that can be passed through the network, and send the onion to the first hop on the circuit.

All of the components of this system will communicate over HTTP (unencrypted!!!) using the built-in Python HTTP server and clients.

## PHASE 0: Setup
1. Send me your github username
1. Download my starter code from Moodle
1. Create your own PRIVATE github repo
1. Add me as a collaborator (`@sidstamm`)
1. Give all your teammates [access to the repo](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-access-to-your-personal-repositories/inviting-collaborators-to-a-personal-repository).
1. Ensure you have python 3 and the `rsa`, `json`, `urllib`, and `sqlite3` packages installed
    - install them via the command line (PowerShell) with `pip install rsa json urllib sqlite3`

## PHASE 1: Getting Started
1. Inspect `onions.py`.  This module contains resources for all the programs.
    * What classes exist in that module?
    * What functionality do the various classes have?
1. Inspect `keymanager.py`
    * What does program this do?
1. Run `keymanager.py` on the command-line (or in vscode).
    * Generate a keypair (this will construct two Pathetic Certificates)
    * EXPORT THEM TO FILES
    * Do not commit your certificates to git.
    * inspect them in your favorite text editor
    * Do not commit your certificates to git.

## PHASE 2: using the keyserver
1. Pick someone in your group to run a copy of the keyserver on one of your laptops.
    * TIP: open a new powershell window, cd into your repo's `onion` folder, then run the script with:

        `python3 ./keyserver.py`

        Leave this running in the powershell window while you do other things.

1. Get the IP address of your laptop (you can use `ipconfig` to find it, and the address should begin with "137.112." when on the RHIT network)
1. Using a web browser, test that you can access the keyserver using your IP address.  For example, if your IP address is `137.112.99.100`, you'd open this URL in Firefox or Chrome or whatever: `http://137.112.99.100:5555/KEYS`

Once you have confirmed that the keyserver is working, edit the `onions.py` file to use your IP address instead of `localhost` in the definition of `CONST_KEYSERVER_URL`.  (Hint: it is near the top of the file.)

1. Add and commit (then push) the changes you made to the `onions.py` file to your repo.
    * Do not commit your certificates to git.
    * Be careful and only add `onions.py` (don't add any other files)
    * Do not commit your certificates to git.
    * push your changes to github after you add and commit


## PHASE 3: small group use of keyserver
 **Everyone in your group should do this phase using the ONE keyserver you set up**.

1. Make sure the `keyserver.py` from PHASE 2 is running.  (Only that one person needs to run the keyserver).
1. Have everyone in your group pull a copy of your repo
1. Run the `keymanager.py` and make a keypair
    * If you already did this, you can `import` your keypair instead of making a new one.
1. Export the keys to save them locally.
1. Have everyone (one at a time) send their keys to the keyserver.
1. Have everyone download all the keys from the server!
1. If you made any changes to the code, add and commit (then push) them to your repo.
    * Do not commit your certificates to git.

At this point, every member of your team should have a `secretcert.json` and `pubcert.json` file that contains their keypair and identity information.
You should also have a `keys-downloaded.json` file with every teammember's rhit ID and public key.

You are ready to encrypt.

## PHASE 4: small group onion node test

### First, your team will make a new program that sends messages to their own `onionNode`:

1. Inspect `onionNode.py`
    * Modify it so anything sent to the node gets printed to the screen.
1. Run an `onionNode.py` in the background.
    * TIP: open a new powershell window, cd into your repo's `onion` folder, then run the script with:

        `python3 ./onionNode.py`

        Leave this running in the powershell window while you do other things.
1. Create a new `onionSender.py` program
    * This will send messages to an onion nodes
    * Start simple: just get it to transmit an unencrypted message to your node.

### Next, update the sender and node code to pass single-layer onions:

1. Read the TODOs in the `onionNode.py` file. 
1. Update `onionNode.py` so it detects when a message is an onion, and then peels it (do the TODOs)
    * Be sure to print what comes out after peeling the onion.
1. Update your `onionSender.py` code to create a single-layer onion around the message it will pass to the node.  Encrypt a message using the `Onion` class, and send an onion to your node.
    * Consider adding a method to `Onion` that does the opposite of `peel()`
    * Test to make sure that you can send a message to your node and the node can peel it.
1. Add and commit (then push) your new `onionSender.py` file (and any other files you changed).
    * Do not commit your certificates to git.
    * Be careful and only add the python files you changed (don't add any other files)

## PHASE 5: multiple hops
Okay, no more hand-holding.  Now you get to be a little creative!

1. First: edit your `onionNode.py` servers to tell the keyserver when they start up and when they shut down.  
    * Continue using your group's keyserver
    * When your node starts up, have it send an `/ONLINE?un=<username>` request to the keyserver. (This puts the node's IP address into the keyserver.)
    * When your node exits, have it send an `/OFFLINE?un=<username>` request.
    * See comment block at the top of `keyserver.py` for details.
1. Edit your `onionSender.py` program to construct a path through each one of your teammates' nodes, and wrap multiple layers into an onion. 
1. Update the sender and your onion node to look up nodes' addresses and keys as necessary from the keyserver.
    * Use the keyserver to find a list of your teammates' keys and their IP addresses.
1. Get everyone in your team to have working senders and nodes.
    * Test with long paths.  Wrap a 10-layer onion that visits each node more than once.
1. Add and commit (then push) any files you changed.
    * Do not commit your certificates to git.


## PHASE 6: random paths
Add "recipient choice" and "random path generation" to your `onionSender.py` program.

1. Update your `onionSender.py` program to get the destination and message content from a command line user. 
1. Also get the path length from the user.
    HINT: `n = int(input('hops? '))`
1. Randomly construct a path and onion for that path.
1. Be sure to print the path on the console so the sender knows where the message should go!
1. Add and commit (then push) any files you changed.
    * Do not commit your certificates to git.

## PHASE 7: CHAOS
Be ready to work with the entire class to making a giant network of onion routing nodes!  We will reproduce phases 5 and 6 in class as a BIG GROUP.  Be ready to:

1. Change the keyserver IP address to one that everyone will use
1. Load your keypair from a file using `keymanager.py`
1. Send your public key cert to the keyserver
1. launch a node that "registers" with the keyserver
1. send and receive messages over the big network!

## SUBMITTING your code
1. Submit a link to your github repo on moodle.  Only one member of your team needs to do this.
