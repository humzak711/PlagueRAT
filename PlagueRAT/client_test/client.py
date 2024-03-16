import socket
import platform
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, Entry, Button
from client_modules.RSAcryptography import cryptography_toolkit

# Message server details
SERVER_HOST: str = '127.0.0.1'
SERVER_PORT: int = 55555

class ChatClient:
    def __init__(self, master: tk.Tk) -> None:
        """
        Initialize the ChatClient.

        Parameters:
        - master (tk.Tk): The Tkinter root window.
        """
        
        # Flag to indicate if OS has been sent to server
        self.OS_detected: bool = False

        # Initialize the GUI
        self.master: tk.Tk = master
        self.master.title('Chat Client')
        self.master.geometry("800x600")  # Set the window size
        self.create_widgets()

        # Set up TCP/IP socket connection to the server
        self.client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((SERVER_HOST, SERVER_PORT))

        # Start a thread to receive messages from the server
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    # OS detection
    def send_OS(self):
        ''' Function to detect and send OS to server '''

         # Get the client's operating system information
        os_info: str = platform.system()

        # Send the operating system information to the server
        #os_info: str = cryptography_toolkit.encrypt_message(os_info, ) 
        self.OS_detected: bool = True
        self.client_socket.send(os_info.encode())

    def create_widgets(self) -> None:
        """
        Create GUI widgets for the ChatClient.
        """
        # Create a styled frame
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")

        frame = ttk.Frame(self.master, style="TFrame")
        frame.pack(fill=tk.BOTH, expand=True)

        # Create a scrolled text widget for displaying messages
        self.message_area: scrolledtext.ScrolledText = scrolledtext.ScrolledText(
            frame, width=80, height=20, wrap=tk.WORD, state=tk.DISABLED  # Set the state to DISABLED
        )
        self.message_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Create a frame for the entry and send button
        entry_frame = ttk.Frame(frame, style="TFrame")
        entry_frame.pack(fill=tk.X)

        # Create an entry widget for user input
        self.entry: Entry = Entry(entry_frame, font=("Helvetica", 14), width=60)
        self.entry.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

        # Create a button widget for sending messages
        send_button: Button = Button(entry_frame, text='Send', command=self.send_message, font=("Helvetica", 14), bg="#4CAF50", fg="white")
        send_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
    def receive_messages(self) -> None:
        """
        Receive and display messages from the server.
        """
        while True:
            # Send OS to server
            if self.OS_detected == False:
                self.send_OS()
            try:
                # Receive a message from the server and display it
                message: str = self.client_socket.recv(1024).decode('utf-8')
                self.message_area.configure(state=tk.NORMAL)  # Set the state to NORMAL to enable editing
                self.message_area.insert(tk.END, message + '\n')
                self.message_area.yview(tk.END)  # Scroll to the bottom
                self.message_area.configure(state=tk.DISABLED)  # Set the state back to DISABLED
            except ConnectionResetError:
                break

    def send_message(self) -> None:
        """
        Send a message to the server.
        """
        # Get the message from the entry widget and send it to the server
        message: str = self.entry.get()
        if message:
            self.client_socket.send(message.encode('utf-8'))
            self.entry.delete(0, tk.END)

# Run the app
if __name__ == '__main__':
    # Create the Tkinter root window and initialize the ChatClient
    root: tk.Tk = tk.Tk()
    chat_client: ChatClient = ChatClient(root)
    root.mainloop()