import re
from socket import *
import threading
import time
import select
import logging
import bcrypt
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama - needed for Windows systems
init(autoreset=True)

# flag to tell if a user is in a group or not
global isInGroup
isInGroup = 0


def establish_connection(server_ip, server_port=15100):
    MAX_RETRIES = 3
    RETRY_DELAY = 3  # seconds
    # Create a TCP/IP socket
    tcp_socket = socket(AF_INET, SOCK_STREAM)

    # Define the server address and port
    server_address = (server_ip, server_port)

    # Attempt to connect to the server
    connected = False
    retries = 0
    while not connected and retries < MAX_RETRIES:
        try:
            print(Fore.YELLOW + Style.BRIGHT + f"Attempting to connect to {server_address}")
            tcp_socket.connect(server_address)
            connected = True
            print(Fore.GREEN + "Connection established.")
        except error as e:
            print(f"Connection failed: {e}")
            retries += 1
            if retries < MAX_RETRIES:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                print(Fore.RED + "Maximum retries reached. Could not establish connection.")
                return None

    return tcp_socket


def send_data(tcp_socket, data, server_ip, server_port=15100):
    if not tcp_socket:
        print("No connection established.")
        return False, tcp_socket

    try:
        # Check if the socket is still connected before sending data
        tcp_socket.sendall(data.encode())
        print("Data sent successfully.")
        return True, tcp_socket
    except error as e:
        print(f"Error sending data: {e}")
        # Attempt to reconnect
        tcp_socket = establish_connection(server_ip, server_port)
        if tcp_socket:
            # Retry sending data after reconnecting
            return send_data(tcp_socket, data, server_ip, server_port)[0], tcp_socket
        else:
            return False, tcp_socket


# Server side of peer
class PeerServer(threading.Thread):

    # Peer server initialization
    def __init__(self, username, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None

    # main method of the peer server thread
    def run(self):

        print(Fore.GREEN + "Peer server started...")

        # gets the ip address of this peer
        # first checks to get it for windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macos devices
        hostname = gethostname()
        try:
            self.peerServerHostname = gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

        # ip address of this peer
        # self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer
        self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))
        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is 
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0 and isInGroup == 0:
                            print(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(messageReceived))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main process of the peer
                            # if the socket that we received the data belongs to the peer that we are chatting with,
                            # enters here and we are not in a group
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                # prints prompt for the incoming chat request
                                print("Incoming chat request from " + self.chattingClientName + " >> ")
                                print("Enter OK to accept or REJECT to reject:  ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are chatting with
                            # and if the user is already chatting with someone else(isChatRequested = 1), then enters here
                            elif s is not self.connectedPeerSocket and (self.isChatRequested == 1 or isInGroup == 1):
                                # sends a busy message to the peer that sends a chat request when this peer is 
                                # already chatting with someone else

                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the user name of the peer trying to connect with you
                                tryingToConnectUserName = messageReceived[2]
                                print(Fore.YELLOW + "[Notification]: " + tryingToConnectUserName + "tried to connect "
                                      + "with you")
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be
                        # shown to the peer of this server
                        elif messageReceived == "OK":
                            self.isChatRequested = 1
                        # if an REJECT message is received then ischatrequested is made 0 so that it can receive any
                        # other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and 
                        # if it is not an empty message, show this message to the user
                        elif messageReceived[:2] != ":q" and len(messageReceived) != 0:
                            print(
                                self.chattingClientName + ": " + messageReceived + "\n")  # print a space after the msg is shown
                        # if the message received is a quit message ':q',
                        # makes ischatrequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(messageReceived) == 2:
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")
            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))


# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False

    # main method of the peer client thread
    def run(self):
        print(Fore.GREEN + "Peer client started...")
        # connects to the server of other peer
        print(self.ipToConnect,self.portToConnect)
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client
        # then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the
            # server this client connects
            requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort) + " " + self.username
            # logs the chat request sent to other peer
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + requestMessage)
            # sends the chat request
            self.tcpClientSocket.send(requestMessage.encode())
            print("Request message " + requestMessage + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
            logging.info(
                "Received from " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + self.responseReceived)
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the
            # connected server
            if self.responseReceived[0] == "OK":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                while self.peerServer.isChatRequested == 1:
                    # message input prompt
                    messageSent = input(self.username + ": ")
                    # sends the message to the connected peer, and logs it
                    self.tcpClientSocket.send(messageSent.encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                    # if the quit message is sent, then the server status is changed to not chatting
                    # and this is the side that is ending the chat
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        break
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                        except BrokenPipeError as bpErr:
                            logging.error("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected
            # peer's server logs the message and then the socket is closed
            elif self.responseReceived[0] == "REJECT":
                self.peerServer.isChatRequested = 0
                print("client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
                print("socket closed")
        # if the client is created with OK message it means that this is the client of receiver side peer so it sends
        # an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == "OK":
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            okMessage = "OK"
            self.tcpClientSocket.send(okMessage.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + okMessage)
            print("Client with OK message is created... and sending messages")
            # client can send messsages as long as the server status is chatting
            while self.peerServer.isChatRequested == 1:
                # input prompt for user to enter message
                messageSent = input(self.username + ": ")
                self.tcpClientSocket.send(messageSent.encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                # if a quit message is sent, server status is changed
                if messageSent == ":q":
                    self.peerServer.isChatRequested = 0
                    self.isEndingChat = True
                    break
            # if server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                self.responseReceived = None
                self.tcpClientSocket.close()


# main process of the peer
class peerMain:

    # peer initializations
    def __init__(self):
        # ip address of the registry
        self.registryName = input("Enter IP address of registry: ")
        # self.registryName = 'localhost'
        # port number of the registry
        self.registryPort = 15100
        # # tcp socket connection to registry
        # self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # self.tcpClientSocket.connect((self.registryName, self.registryPort))

        self.tcpClientSocket = establish_connection(self.registryName, self.registryPort)
        # initializes udp socket which is used to send hello messages
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        self.udpClientSocket.bind(('', 0))

        self.udpPortNum = self.udpClientSocket.getsockname()[1]
        # udp port of the registry
        self.registryUDPPort = 15200
        # login info of the peer
        self.loginCredentials = (None, None)
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None
        # group linked list left and right
        # self.left_group_member = [None, None]
        self.right_group_member = [None, None]
        # username of the peer if logged in (it will be needed in the chat room)
        self.userName = None

        choice = "0"
        # log file initialization
        logging.basicConfig(filename="peer.log", level=logging.INFO)
        # as long as the user is not logged out, asks to select an option in the menu
        while choice != "3":
            # menu selection prompt
            choice = input("Choose: \nCreate account: 1\nLogin: 2\nExit: 3\nSearch: 4\nStart a chat: 5\nJoin Chat "
                           "Room: 6\nCreate Chat room: 7\nList online peers: 8\nList groups: 9\n")
            # if choice is 1, creates an account with the username
            # and password entered by the user
            if choice == "1":
                username = input("username: ")
                password = input("password: ")

                self.createAccount(username, password)
            # if choice is 2 and user is not logged in, asks for the username
            # and the password to login
            elif choice == "2" and not self.isOnline:
                username = input("username: ")
                password = input("password: ")
                # asks for the port number for server's tcp socket
                # peerServerPort = int(input("Enter a port number for peer server: "))
                peerServerPort = self.find_available_port()[0]
                print("Your assigned peer server port is ", peerServerPort)

                status = self.login(username, password, peerServerPort)
                # is user logs in successfully, peer variables are set
                if status == 1:
                    self.userName = username
                    self.isOnline = True
                    self.loginCredentials = (username, password)
                    self.peerServerPort = peerServerPort
                    # creates the server thread for this peer, and runs it
                    self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort)
                    self.peerServer.start()
                    # hello message is sent to registry
                    self.sendHelloMessage()
            # if choice is 3 and user is logged in, then user is logged out
            # and peer variables are set, and server and client sockets are closed
            elif choice == "3" and self.isOnline:
                self.logout(1)
                self.isOnline = False
                self.loginCredentials = (None, None)
                self.peerServer.isOnline = False
                self.peerServer.tcpServerSocket.close()
                if self.peerClient is not None:
                    self.peerClient.tcpClientSocket.close()
                print(Fore.GREEN + "Logged out successfully")
            # is peer is not logged in and exits the program
            elif choice == "3":
                self.logout(2)
            # if choice is 4 and user is online, then user is asked
            # for a username that is wanted to be searched
            elif choice == "4" and self.isOnline:
                username = input("Username to be searched: ")
                searchStatus = self.searchUser(
                    username)  # 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
                # if user is found its ip address is shown to user
                if searchStatus is not None and searchStatus != 0:
                    print("IP address of " + username + " is " + searchStatus)
            # if choice is 5 and user is online, then user is asked
            # to enter the username of the user that is wanted to be chatted
            elif choice == "5" and self.isOnline:
                username = input("Enter the username of user to start chat: ")
                searchStatus = self.searchUser(username)
                # if searched user is found, then its ip address and port number is retrieved
                # and a client thread is created
                # main process waits for the client thread to finish its chat
                if searchStatus is not None and searchStatus != 0:
                    searchStatus = searchStatus.split(":")
                    self.peerClient = PeerClient(searchStatus[0], int(searchStatus[1]), self.loginCredentials[0],
                                                 self.peerServer, None)
                    self.peerClient.start()
                    # l = Listener(self.tcpClientSocket)
                    # l.start()
                    self.peerClient.join()
                    # l.turnoff(False)
                    # l.join()

            # if this is the receiver side then it will get the prompt to accept an incoming request during the main
            # loop that's why response is evaluated in main process not the server thread even though the prompt is
            # printed by server if the response is ok then a client is created for this peer with the OK message and
            # that's why it will directly send an OK message to the requesting side peer server and waits for the
            # user input main process waits for the client thread to finish its chat
            elif choice == "OK" and self.isOnline:
                okMessage = "OK " + self.loginCredentials[0]
                logging.info("Send to " + self.peerServer.connectedPeerIP + " -> " + okMessage)
                self.peerServer.connectedPeerSocket.send(okMessage.encode())
                self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort,
                                             self.loginCredentials[0], self.peerServer, "OK")
                self.peerClient.start()
                self.peerClient.join()
            # if user rejects the chat request then reject message is sent to the requester side
            elif choice == "REJECT" and self.isOnline:
                self.peerServer.connectedPeerSocket.send("REJECT".encode())
                self.peerServer.isChatRequested = 0
                logging.info("Send to " + self.peerServer.connectedPeerIP + " -> REJECT")
            # if choice is cancel timer for hello message is cancelled
            elif choice == "CANCEL":
                self.timer.cancel()
                break
            # if peer wants to join a group
            elif choice == "6" and self.isOnline:
                group_name = input("Enter the group you want to join\n")
                ret = self.join_group(group_name)
                if ret == 1:
                    group_chat = GroupChat(self.udpClientSocket, self.right_group_member,
                                           self.tcpClientSocket, group_name, self.userName)
                    group_chat.start()
                    group_chat.join()
                elif ret == 0:
                    print("Group you are searching for is not found")
                elif ret == -1:
                    print("Your Join request to group is rejected")
            # if peer wants to create a group
            elif choice == "7" and self.isOnline:
                group_name = input("Enter the group name you want to create\n")
                ret = self.create_group(group_name)
                if ret == 1:
                    print("Group Created Successfully")
                    group_chat = GroupChat(self.udpClientSocket, self.right_group_member,
                                           self.tcpClientSocket, group_name, self.userName, True)

                    group_chat.start()
                    group_chat.join()
                elif ret == 0:
                    print("Group already exists")

            # if peer wants to display a list of online peers
            elif choice == "8":
                ret = self.get_online_peers()
                if (isinstance(ret, int)):
                    print(Fore.RED + "No Peers Available at The Moment")
                    continue
                for i in ret:
                    print(Fore.BLUE + i)

            # if peer wants to display a list of groups
            elif choice == "9":
                ret = self.get_groups()
                if (isinstance(ret, int)):
                    print(Fore.RED + "No Groups Available")
                    continue
                for i in ret:
                    print(Fore.BLUE + i)

        # if main process is not ended with cancel selection
        # socket of the client is closed
        if choice != "CANCEL":
            self.tcpClientSocket.close()

    # account creation function
    def createAccount(self, username, password):
        # Minimum eight characters, at least one letter and one number:
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
        if re.match(pattern, password):
            pass
        else:
            print(Fore.CYAN + "Pass must be minimum eight characters, at least one letter and one number")
            return
        # hash password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
        # join message to create an account is composed and sent to registry
        # if response is success then informs the user for account creation
        # if response is exist then informs the user for account existence
        message = "JOIN " + username + " " + hashed_password + " " + salt.decode()
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "join-success":
            print(Fore.GREEN + "Account created...")
        elif response == "join-exist":
            print(Fore.RED + "choose another username or login...")

    # login function
    def login(self, username, password, peerServerPort):
        # hash password

        # a login message is composed and sent to registry
        # an integer is returned according to each response
        message = "SALT " + username
        # self.tcpClientSocket.send(message.encode())

        self.tcpClientSocket = send_data(self.tcpClientSocket, message, self.registryName, self.registryPort)[1]
        salt = self.tcpClientSocket.recv(1024).decode()

        hashed_password = bcrypt.hashpw(password.encode(), salt.encode()).decode()
        message = "LOGIN " + username + " " + hashed_password + " " + str(peerServerPort) + " " + str(self.udpPortNum)
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "login-success":
            print(Fore.GREEN + "Logged in successfully...")
            return 1
        elif response == "login-account-not-exist":
            print(Fore.RED + "Account does not exist...")
            return 0
        elif response == "login-online":
            print(Fore.CYAN + "Account is already online...")
            return 2
        elif response == "login-wrong-password":
            print(Fore.RED + "Wrong password...")
            return 3

    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + self.loginCredentials[0]
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())

    # function for searching an online user
    def searchUser(self, username):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[0] == "search-success":
            print(username + " is found successfully...")
            return response[1]
        elif response[0] == "search-user-not-online":
            print(username + " is not online...")
            return 0
        elif response[0] == "search-user-not-found":
            print(username + " is not found")
            return None

    # function for sending hello message
    # a timer thread is used to send hello messages to udp socket of registry
    def sendHelloMessage(self):
        message = "HELLO " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryUDPPort) + " -> " + message)
        self.udpClientSocket.sendto(message.encode(), (self.registryName, self.registryUDPPort))
        self.timer = threading.Timer(1, self.sendHelloMessage)
        self.timer.start()

    def join_group(self, group_name="hard code"):
        message = "JOIN-GROUP " + group_name
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        # if joined give the peer the address of the last group member in the linked list (group)
        print(response)
        if response[0] == "SUCCESS":
            self.right_group_member[0] = response[1]
            self.right_group_member[1] = int(response[2])
            print("my right", self.right_group_member)
            return 1
        elif response[0] == "JOIN-REJECTED":
            return -1
        elif response[0] == "GROUP-NOT-FOUND":
            return 0

    def create_group(self, group_name):
        message = "CREATE-GROUP " + group_name
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        if response[0] == "CREATED":
            return 1
        elif response[0] == "GROUP-EXISTS":
            return 0

    def get_online_peers(self):
        message = "GET-ONLINE-PEERS"
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        if response[0] == "NO-ONLINE-PEERS":
            return 0
        else:
            return response

    def get_groups(self):
        message = "GET-GROUPS"
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        if response[0] == "NO-GROUPS":
            return 0
        else:
            return response

    def find_available_port(self):
        available_ports = []
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.bind(('', 0))  # Try binding to the port
            port = s.getsockname()[1]
            available_ports.append(port)
        except error as e:
            print("No ports available")
            pass  # Port is not available, continue checking the next one
        finally:
            s.close()  # Close the socket after checking availability
        return available_ports


class GroupChat(threading.Thread):
    def __init__(self, udp_socket, right, centralized_server_socket, group_name, user_name, is_host=False):
        super().__init__()
        self.udpClientSocket = udp_socket
        self.right = right
        self.tcpClientSocket = centralized_server_socket
        self.is_host = is_host
        self.groupName = group_name
        self.userName = user_name
        self.sentMessages = {}
        self.receivedMessages = []
        global isInGroup
        isInGroup = 1

    def run(self):
        monitor_thread = threading.Thread(target=self.monitor)
        read_thread = threading.Thread(target=self.read)
        monitor_thread.start()
        read_thread.start()
        while self.right[0] is not None or self.is_host:
            print(self.right)
            msg = input("[" + self.groupName + "]: ")

            if msg == ":q":
                messageToServer = "LEAVE-GROUP " + self.groupName
                self.tcpClientSocket.send(messageToServer.encode())
                break
            # ------------------
            current_utc_time = datetime.utcnow()
            msg = str(current_utc_time) + "[" + self.userName + "]" + " " + msg
            if self.right[0] is not None:
                self.udpClientSocket.sendto(msg.encode(), (self.right[0], self.right[1]))
                print(Fore.CYAN + "send to the right")
            self.sentMessages[msg] = 0
            timer = threading.Timer(5.0, self.check_message, args=(msg,))
            timer.start()
        print("got out of run loop")

    def read(self):
        while self.right[0] is not None or self.is_host:
            self.udpClientSocket.setblocking(False)
            try:
                message, clientAddress = self.udpClientSocket.recvfrom(2048)
                decoded_message = message.decode()
                print(Fore.LIGHTYELLOW_EX + "for debug" + decoded_message)
                # if it was a message that I sent
                if decoded_message in self.sentMessages.keys():
                    print(Fore.LIGHTYELLOW_EX + "message i sent")
                    # mark that the message you sent was successfully sent to all the peers
                    self.sentMessages[decoded_message] = 1
                    continue
                # duplicate message that I received
                elif decoded_message in self.receivedMessages:
                    print(Fore.LIGHTYELLOW_EX + "message i recieved")
                    if self.right[0] is not None:
                        self.udpClientSocket.sendto(message, (self.right[0], self.right[1]))
                # new message that I didn't receive
                else:
                    print(Fore.LIGHTYELLOW_EX + "new message")
                    if self.right[0] is not None:
                        self.udpClientSocket.sendto(message, (self.right[0], self.right[1]))
                    self.receivedMessages.append(decoded_message)
                    if len(self.receivedMessages) >= 101:
                        self.receivedMessages.pop(0)
                    index = decoded_message.find('[')
                    print(Fore.YELLOW + decoded_message[index:])
                # Process the received message
            except error as e:
                # print("no data")
                pass

        print("got out of read loop")

    def monitor(self):
        while True:
            try:
                print("waiting for msg")

                msg = self.tcpClientSocket.recv(1024).decode().split()
                print(msg)
                if msg[0] == "MAKE-HOST":
                    self.is_host = True
                if msg[0] == "CONNECT-RIGHT":
                    self.right[0] = msg[1]
                    self.right[1] = int(msg[2])
                elif msg[0] == "LEAVE-GRANTED":
                    self.is_host = False
                    self.right[0] = self.right[1] = None
                    self.is_host = False
                    print(Fore.BLUE + "You left the group")
                    break
                elif msg[0] == "HOST":
                    print("you are the host now")
                    self.is_host = True


            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
        print("got out of monitor loop")
        global isInGroup
        isInGroup = 0

    def check_message(self, msg):
        # Replace this with your condition checking logic
        if self.sentMessages[msg] == 0:
            print(Fore.RED + "Your message " + msg + "Failed to send")

        self.sentMessages.pop(msg)


# class to get messages from the centralized server
class Listener(threading.Thread):
    def __init__(self, centralized_server_socket):
        super().__init__()
        self.tcpClientSocket = centralized_server_socket
        self.busy = True

    def run(self):
        while self.busy:
            msg = self.tcpClientSocket.recv(1024)
            print(msg.decode())

    def turnoff(self, is_busy):
        self.busy = is_busy


# peer is started
# to change peer pointers on leave
GroupChatlist = {}
main = peerMain()
