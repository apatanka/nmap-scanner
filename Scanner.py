import nmap
import ipaddress

scanner = nmap.PortScanner()
print("------------------------------------------------------------------------------\n")
print("               Welcome to the beginners nmap automation tool\n")
print("------------------------------------------------------------------------------\n")


ipAddress = input("Please enter the IP address you wish to scan: ")

# if the supplied IP is valied perform program will continue with scan type

try:
    ip = ipaddress.ip_address(ipAddress)
    print("You entered IP: ", ipAddress)
    type(ipAddress)

    response = input(""""\n Please enter the type of scan you want to run
                            1. SYN ACK Scan
                            2. UDP Scan
                            3. Comprehensive Scan \n""")
    print("You have selected option: ", response)
    
    # performs a SYN ACK scan -sS
    
    if response == '1':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ipAddress, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ipAddress].state())
        print(scanner[ipAddress].all_protocols())
        print("Open Ports: ", scanner[ipAddress]['tcp'].keys())
        
    # performs a UDP scan -sU
    
    elif response == '2':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ipAddress, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ipAddress].state())
        print(scanner[ipAddress].all_protocols())
        print("Open Ports: ", scanner[ipAddress]['udp'].keys())
        
    # performs a Comprehensive scan -v -sS -sV -sC -A -O
    
    elif response == '3':
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(ipAddress, '1-1024', '-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ipAddress].state())
        print(scanner[ipAddress].all_protocols())
        print("Open Ports: ", scanner[ipAddress]['tcp'].keys())
        
    # Error in case user enters any other value for type of scan
    
    else:
        response >= '4'
        print("Please enter a valid option...")
        
# Error statement if the IP is not valid

except ValueError:
    print("Entered IP address is not valid")

