from modules.PlagueRCE import PlagueRCE

# Start the server
if __name__ == '__main__':

    # Obtain host information 
    host_ip: str = input('Enter host ip address: ') 
    host_port: int = int(input('Enter host port: '))
     
    # Start the server
    PlagueRCE_server: PlagueRCE = PlagueRCE(host_ip, host_port)
    PlagueRCE_server.start_server()
