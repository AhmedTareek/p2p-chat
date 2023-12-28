'''
    ##  Implementation of registry
    ##  150114822 - Eren Ulaş
'''
import time
from socket import *
import threading
import select
import logging
import db


# This class is used to process the peer messages sent to registry
# for each peer connected to registry, a new client thread is created
class ClientThread(threading.Thread):
    # initializations for client thread
    def __init__(self, ip, port, tcpClientSocket):
        threading.Thread.__init__(self)
        # ip of the connected peer
        self.ip = ip
        # port number of the connected peer
        self.port = port
        # socket of the peer
        self.tcpClientSocket = tcpClientSocket
        # username, online status and udp server initializations
        self.username = None
        self.isOnline = True
        self.udpServer = None
        print("New thread started for " + ip + ":" + str(port))

    # main of the thread
    def run(self):
        # locks for thread which will be used for thread synchronization
        checking_thread = threading.Thread(target=self.check_pending_peers)
        checking_thread.start()
        checking_leaving = threading.Thread(target=self.check_leaving_peers)
        checking_leaving.start()
        self.lock = threading.Lock()
        print("Connection from: " + self.ip + ":" + str(port))
        print("IP Connected: " + self.ip)
        sending = SendToPeer(tcpClientSocket)
        while True:

            try:
                # check if there are any pending peers want to connect with you in a group

                # waits for incoming messages from peers

                message = self.tcpClientSocket.recv(1024).decode().split()
                if sending.is_running:
                    sending.turnoff(False)
                    sending.join()
                logging.info("Received from " + self.ip + ":" + str(self.port) + " -> " + " ".join(message))
                #   JOIN    #
                if message[0] == "JOIN":
                    # join-exist is sent to peer,
                    # if an account with this username already exists

                    if db.is_account_exist(message[1]):
                        response = "join-exist"
                        print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # join-success is sent to peer,
                    # if an account with this username is not exist, and the account is created
                    else:
                        db.register(message[1], message[2], message[3])
                        response = "join-success"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                #   LOGIN    #
                elif message[0] == "LOGIN":
                    # login-account-not-exist is sent to peer,
                    # if an account with the username does not exist
                    if not db.is_account_exist(message[1]):
                        response = "login-account-not-exist"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-online is sent to peer,
                    # if an account with the username already online
                    elif db.is_account_online(message[1]):
                        response = "login-online"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-success is sent to peer,
                    # if an account with the username exists and not online
                    else:
                        # retrieves the account's password, and checks if the one entered by the user is correct
                        retrievedPass = db.get_password(message[1])
                        # if password is correct, then peer's thread is added to threads list
                        # peer is added to db with its username, port number, and ip address
                        if retrievedPass == message[2]:
                            self.username = message[1]
                            self.lock.acquire()
                            try:
                                tcpThreads[self.username] = self
                            finally:
                                self.lock.release()

                            db.user_login(message[1], self.ip, message[3], message[4])
                            # login-success is sent to peer,
                            # and a udp server thread is created for this peer, and thread is started
                            # timer thread of the udp server is started
                            response = "login-success"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                            self.udpServer = UDPServer(self.username, self.tcpClientSocket)
                            self.udpServer.start()
                            self.udpServer.timer.start()
                        # if password not matches and then login-wrong-password response is sent
                        else:
                            response = "login-wrong-password"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                #   LOGOUT  #
                elif message[0] == "LOGOUT":
                    # if user is online,
                    # removes the user from onlinePeers list
                    # and removes the thread for this user from tcpThreads
                    # socket is closed and timer thread of the udp for this
                    # user is cancelled
                    if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
                        db.user_logout(message[1])
                        self.lock.acquire()
                        try:
                            if message[1] in tcpThreads:
                                del tcpThreads[message[1]]
                        finally:
                            self.lock.release()
                        print(self.ip + ":" + str(self.port) + " is logged out")
                        self.tcpClientSocket.close()
                        self.udpServer.timer.cancel()
                        break
                    else:
                        self.tcpClientSocket.close()
                        break
                #   SEARCH  #
                elif message[0] == "SEARCH":
                    # checks if an account with the username exists
                    if db.is_account_exist(message[1]):
                        # checks if the account is online
                        # and sends the related response to peer
                        if db.is_account_online(message[1]):
                            # 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                            peer_info = db.get_peer_ip_port(message[1])
                            response = "search-success " + peer_info[0] + ":" + peer_info[1]
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                            # sending.start()
                        else:
                            response = "search-user-not-online"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                    # enters if username does not exist 
                    else:
                        response = "search-user-not-found"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                # SALT #
                elif message[0] == "SALT":
                    salt = db.get_salt(message[1])
                    self.tcpClientSocket.send(salt.encode())
                # join a group #
                elif message[0] == "JOIN-GROUP":
                    if not db.is_group_exists(message[1]):
                        res = "GROUP-NOT-FOUND"
                        self.tcpClientSocket.send(res.encode())
                    else:
                        peer_username = db.get_last_peer_in_group(message[1])
                        # self.lock.acquire()
                        pendingPeers[peer_username] = self.username
                        # self.lock.release()

                        while True:
                            print("\rJoining ", end='', flush=True)
                            time.sleep(0.5)
                            print("\rJoining . ", end='', flush=True)
                            time.sleep(0.5)
                            print("\rJoining .. ", end='', flush=True)
                            time.sleep(0.5)
                            print("\rJoining ... ", end='', flush=True)
                            time.sleep(0.5)
                            print("peer status keys ", peerStatus.keys())
                            if self.username in peerStatus.keys():
                                stat = peerStatus[self.username]
                                print("stat is ", stat)
                                # self.lock.acquire()
                                del peerStatus[self.username]
                                # self.lock.release()
                                break
                        print("got out of the loop")
                        if stat == 1:
                            peer_addr = db.get_host_ip_udp_port(message[1])
                            res = "SUCCESS " + peer_addr[0] + " " + peer_addr[1]
                            self.tcpClientSocket.send(res.encode())
                            db.add_peer_in_group(message[1], self.username)
                        elif stat == 0:
                            res = "JOIN-REJECTED"
                            self.tcpClientSocket.send(res.encode())

                # create a group #
                elif message[0] == "CREATE-GROUP":
                    if db.is_group_exists(message[1]):
                        res = "GROUP-EXISTS"
                        self.tcpClientSocket.send(res.encode())
                    else:
                        db.add_group(message[1], self.username)
                        res = "CREATED"
                        self.tcpClientSocket.send(res.encode())

                # get online peers #
                elif message[0] == "GET-ONLINE-PEERS":
                    online_peers = db.get_online_peers()
                    if len(online_peers) == 0:
                        response = "NO-ONLINE-PEERS"
                        self.tcpClientSocket.send(response.encode())
                    else:
                        response = online_peers
                        self.tcpClientSocket.send(response.encode())

                elif message[0] == "LEAVE-GROUP":
                    # if the peer is the last one in the group (connected to the host)
                    if db.get_last_peer_in_group(message[1]) == self.username:
                        # remove this peer from the group list
                        db.remove_last_from_group(message[1])
                        # get the new last peer in the group
                        last = db.get_last_peer_in_group(message[1])
                        # get the address of the host
                        host = db.get_host_ip_udp_port(message[1])
                        # add
                        updateRightPeer[last] = host
                        # wait to make sure he left
                        # -- write the code to wait here
                        while last in updateRightPeer.keys():
                            time.sleep(1)
                        response = "LEAVE-GRANTED"
                        self.tcpClientSocket.send(response.encode())
                    # if the peer leaving is the host
                    elif db.get_peer_ip_udp_port(self.username) == db.get_host_ip_udp_port(message[1]):
                        # you will have to make a new one a host or if he is the only one left delete the group
                        pass
                    # normal peer in the group
                    else:
                        # get the peer after the current peer
                        after = db.get_peer_after_in_group(message[1], self.username)
                        # get the address of the after peer
                        after_add = db.get_peer_ip_udp_port(after)
                        # get the peer before the current peer
                        before = db.get_peer_before_in_group(message[1], self.username)
                        updateRightPeer[before] = after_add
                        # wait to make sure he left
                        # -- write the code to wait here
                        while before in updateRightPeer.keys():
                            time.sleep(1)
                        # remove the peer from the group list in the database
                        db.remove_peer_from_group(message[1],self.username)
                        response = "LEAVE-GRANTED"
                        self.tcpClientSocket.send(response.encode())


                    # else:
                    # complete


            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))

                # function for resettin the timeout for the udp timer thread

    def resetTimeout(self):
        self.udpServer.resetTimer()

    def check_pending_peers(self):
        while True:
            if self.username is None:
                name = "None"
            else:
                name = self.username
            savedPeer = ""
            # self.lock.acquire()
            if self.username in pendingPeers:
                savedPeer = pendingPeers[self.username]
                del pendingPeers[self.username]
            # self.lock.release()
            time.sleep(1)
            if savedPeer != "":
                peer_data = db.get_peer_ip_udp_port(savedPeer)
                msg = "CONNECT-RIGHT " + peer_data[0] + " " + peer_data[1]
                # send message to peer to connect the new user
                self.tcpClientSocket.send(msg.encode())
                print("sent the message to the peer to connect-left")

                res = "CONNECTED-SUCCESS"
                res2 = "SUCCESS " + peer_data[0] + " " + peer_data[1]
                self.tcpClientSocket.send(res.encode())
                self.tcpClientSocket.send(res2.encode())
                print("recived response", res)
                if res == "CONNECTED-SUCCESS":
                    peerStatus[savedPeer] = 1
                elif res == "CONNECTED-FAILED":
                    peerStatus[savedPeer] = 0
                # self.lock.release()
                print("peer status is", peerStatus[savedPeer])

    def check_leaving_peers(self):
        while True:
            address = ""
            # self.lock.acquire()
            if self.username in updateRightPeer.keys():
                address = updateRightPeer[self.username]
                del updateRightPeer[self.username]
            # self.lock.release()
            time.sleep(1)
            if address != "":
                msg = "CONNECT-RIGHT " + address[0] + " " + address[1]
                self.tcpClientSocket.send(msg.encode())
                print("sent the message to the peer to update right connection")
                res = "CONNECTED-SUCCESS"
                print("recived response", res)


# a new class to allow sending messages to user when he is chatting
class SendToPeer(threading.Thread):
    def __init__(self, tcp_client_socket):
        super().__init__()
        self.chatting = True
        self.tcpClientSocket = tcp_client_socket
        self.is_running = False

    def run(self):
        self.is_running = True
        while self.chatting:
            msg = input("enter a msg to send to user")
            self.tcpClientSocket.send(msg.encode())

    def turnoff(self, is_chatting):
        self.chatting = is_chatting
        self.is_running = False


# implementation of the udp server thread for clients
class UDPServer(threading.Thread):

    # udp server thread initializations
    def __init__(self, username, clientSocket):
        threading.Thread.__init__(self)
        self.username = username
        # timer thread for the udp server is initialized
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.tcpClientSocket = clientSocket

    # if hello message is not received before timeout
    # then peer is disconnected
    def waitHelloMessage(self):
        if self.username is not None:
            db.user_logout(self.username)
            if self.username in tcpThreads:
                del tcpThreads[self.username]
        self.tcpClientSocket.close()
        print("Removed " + self.username + " from online peers")

    # resets the timer for udp server
    def resetTimer(self):
        self.timer.cancel()
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.timer.start()


# tcp and udp server port initializations
print("Registy started...")
port = 15100
portUDP = 15200

# db initialization
db = db.DB()

# gets the ip address of this peer
# first checks to get it for windows devices
# if the device that runs this application is not windows
# it checks to get it for macos devices
hostname = gethostname()
try:
    host = gethostbyname(hostname)
except gaierror:
    import netifaces as ni

    host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

print("Registry IP address: " + host)
print("Registry port number: " + str(port))

# onlinePeers list for online account
onlinePeers = {}
# accounts list for accounts
accounts = {}
# tcpThreads list for online client's thread
tcpThreads = {}  # it's a shared resource within all threads --> modify it using LOCKS
# list of peers who want to join a group
pendingPeers = {}
# list of Peerstatus
peerStatus = {}
# peers that will be disconnected
updateRightPeer = {}

# tcp and udp socket initializations
tcpSocket = socket(AF_INET, SOCK_STREAM)
udpSocket = socket(AF_INET, SOCK_DGRAM)
tcpSocket.bind((host, port))
udpSocket.bind((host, portUDP))
tcpSocket.listen(5)

# input sockets that are listened
inputs = [tcpSocket, udpSocket]

# log file initialization
logging.basicConfig(filename="registry.log", level=logging.INFO)

# as long as at least a socket exists to listen registry runs
while inputs:

    # print("Listening for incoming connections...")
    # monitors for the incoming connections
    readable, writable, exceptional = select.select(inputs, [], [])
    for s in readable:
        # if the message received comes to the tcp socket
        # the connection is accepted and a thread is created for it, and that thread is started
        if s is tcpSocket:
            tcpClientSocket, addr = tcpSocket.accept()
            newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
            newThread.start()  # invoke the object run method in a separate thread
        # if the message received comes to the udp socket
        elif s is udpSocket:
            # received the incoming udp message and parses it
            message, clientAddress = s.recvfrom(1024)
            message = message.decode().split()
            # checks if it is a hello message
            if message[0] == "HELLO":
                # checks if the account that this hello message 
                # is sent from is online
                if message[1] in tcpThreads:
                    # resets the timeout for that peer since the hello message is received
                    tcpThreads[message[1]].resetTimeout()
                    # print("Hello is received from " + message[1])
                    logging.info(
                        "Received from " + clientAddress[0] + ":" + str(clientAddress[1]) + " -> " + " ".join(message))

# registry tcp socket is closed
tcpSocket.close()
