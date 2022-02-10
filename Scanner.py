import nmap

scanner = nmap.PortScanner()
print("------------------------------------------------------------------------------\n")
print("               Welcome to the beginners nmap automation tool\n")
print("------------------------------------------------------------------------------\n")


ipAddress = input("Please enter the IP address you wish to scan: ")
print("You entered IP: ", ipAddress)
type(ipAddress)

response = input(""""\n Please enter the type of scan you want to run
                        1. SYN ACK Scan
                        2. UDP Scan
                        3. Comprehensive Scan \n""")
print("You have selected option: ", response)

if response == '1':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports: ", scanner[ipAddress]['tcp'].keys())
elif response == '2':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports: ", scanner[ipAddress]['udp'].keys())
elif response == '3':
    print("Nmap version: ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports: ", scanner[ipAddress]['tcp'].keys())
else:
    response >= '4'
    print("Please enter a valid option...")
