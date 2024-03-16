from modules.PlagueRCE import PlagueRCE

# Start the server
if __name__ == '__main__':

    # Obtain host information 
    host_ip: str = '127.0.0.1' # input('Enter host ip address: ') 
    host_port: int = 55555 # int(input('Enter host port: '))
     
    # Start the server
    PlagueRCE_server: PlagueRCE = PlagueRCE(host_ip, host_port)
    PlagueRCE_server.start_server()

# To do:
# Bug hunt and thoroughly test the server
# Fill up the exploit toolkit with windows and linux CVE's
# Build the payload builder