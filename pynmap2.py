#!/usr/bin/python3
import os,nmap3,pyfiglet
nmap = nmap3.Nmap()
pyfiglet.print_figlet("PyNmap")
try:
    def save():
        global file
        file = input("Would you like to save the scan results to a file [y/n]: ")
    def remove():
        print("\nGoodbye...")
        exit()
    print("Welcome to PyNmap v1.1 \n Choose only one number at a time \n Make sure to scan targets legally and with permission")
    print('------------------------------------------------------------------')
    answer = input("   [1] OS and Version detection \n   [2] Port Scan \n   [3] Host Discovery \n   [4] Scan Techniques \n   [5] Exit Scanner \n   Enter a number to choose what scan you would like to initiate: ") 
    print('\n------------------------------------------------------------------------------')
    #[1] OS detection
    if answer == "1":
        ask = input("\nConfigure OS Detection Scan: \n   [1] Enable OS detection (-O) \n   [2] Enable Service Version detection (-sV) \n   [3] Identify Nmap's Version (-V) \n   [q] Quit Scan \n   Choose an option: ")
        if ask == "q":
            remove()
        elif ask == "1":
            print('\n--------------------------------------------')
            print("\nOS detection (-O) ")
            hostname = input("Enter the target's IP Address or domain: ")
            if hostname == "q":
                remove()
            print('\n---------------------------------------------')
            save() 
            if file == "y":
                print('\n-----------------------------------------')
                results = nmap.nmap_os_detection(hostname, args = "-oN OSdetection ")
                print("The output has been saved to the file OSdetection.")
                os.system("cat OSdetection")
            elif file == "n":
                results = nmap.nmap_os_detection(hostname, args = "-oN OSdetection ")
                os.system("cat OSdetection ; rm OSdetection")
            else:
                raise ValueError
        elif ask == "2":
            print('\n--------------------------------------------')
            print("\nService Version detection (-sV) ")
            hostname = input("Enter the target's IP Address or domain: ")
            print('\n-------------------------------------------')
            save() 
            if file == "y":
                print("\nSave to file (-oN) ")
                print('\n----------------------------------------')
                results = nmap.nmap_version_detection(hostname, args = "-oN SVdetection")
                print("The output has been saved to the file SVdetection.")
                os.system("cat SVdetection")
            elif file == "n":
                results = nmap.nmap_version_detection(hostname, args = "-oN SVdetection")
                os.system("cat SVdetection ; rm SVdetection")
            else:
                raise ValueError
        elif ask == "3":
            print('\n-----------------------------------------')
            os.system("nmap -V")
        else:
            raise ValueError
    #[2] Port scan
    if answer == "2":
        ask = input("\nConfigure Port Scan: \n   [1] Fast Scan - 100 ports (-F) \n   [q] Quit scan \n   Choose an option: ")
        if ask != "1":
            remove()
        elif ask == "1":
            print('\n--------------------------------------------')
            print("\nFast Scan - 100 ports (-F) ")
            hostname = input("Enter the target's IP Address or domain: ")
            print('\n---------------------------------------------')
            save() 
            if file == "y":
                print('\n----------------------------------------')
                results = nmap.scan_top_ports(hostname, args = "-oN FastScan")
                print("The output has been saved to the file FastScan.")
                os.system("cat FastScan")
            elif file == "n":
                results = nmap.scan_top_ports(hostname, args = "-oN FastScan")
                os.system("cat FastScan ; rm FastScan")
            else:
                raise ValueError
    #[3] Host Discovery
    if answer == "3":
        ask = input("Configure Host Discovery Scan: \n   [1] Only port scan (-Pn) \n   [2] Only host discover (-sn) \n   [3] ARP Discovery \n   [4] Disable DNS (-n) \n   [q] Quit Scan \n   Choose an option: ")
        if ask == "1" or ask == "2" or ask == "3" or ask == "4":
            pass
        else:
            remove()
        if ask == "1":
            print('\n---------------------------------------------')
            print("\nOnly port scan (-Pn) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapHostDiscovery()
            print('\n-----------------------------------------------')
            save() 
            if file == "y":
                print('\n----------------------------------------')
                results = nmap.nmap_portscan_only(hostname, args = "-oN OnlyPortScan") 
                print("The output has been saved to the file OnlyPortScan.")
                os.system("cat OnlyPortScan")
            elif file == "n":
                results = nmap.nmap_portscan_only(hostname,args="-oN OnlyPortScan")
                os.system("cat OnlyPortScan ; rm OnlyPortScan")
            else:
                raise ValueError
        elif ask == "2": 
            print('\n---------------------------------------------')
            print("\nOnly host discover(-sn) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapHostDiscovery()
            print('\n-----------------------------------------------')
            save() 
            if file == "y":
                print('\n----------------------------------------')
                results = nmap.nmap_no_portscan(hostname, args = "-oN OnlyHostDiscover") 
                print("The output has been saved to the file OnlyHostDiscover.")
                os.system("cat OnlyHostDiscover")
            elif file == "n":
                results = nmap.nmap_no_portscan(hostname, args="-oN OnlyHostDiscover")
                os.system("cat OnlyHostDiscover ; rm OnlyHostDiscover")
            else:
                remove()
        elif ask == "3":
            print('\n--------------------------------------------')
            print("\nARP Discovery (-PR) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapHostDiscovery()
            print('\n-----------------------------------------------')
            save()
            if file == "y":
                print('\n----------------------------------------')
                results = nmap.nmap_arp_discovery(hostname, args = "-oN ARPDiscovery") 
                print("The output has been saved to the file ARPDiscovery.")
                os.system("cat ARPDiscovery")
            elif file == "n":
                results = nmap.nmap_arp_discovery(hostname, args = "-oN ARPDiscovery")
                os.system("cat ARPDiscovery ; rm ARPDiscovery")
            else:
                remove()
        elif ask == "4":
            print('\n--------------------------------------------')
            print("\nDisable Dns (-n) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapHostDiscovery()
            print('\n-----------------------------------------------')
            save() 
            if file == "y":
                print('\n----------------------------------------')
                results = nmap.nmap_disable_dns(hostname, args = "-oN DisableDNS") 
                print("The output has been saved to the file DisableDNS.")
                os.system("cat DisableDNS")
            elif file == "n":
                results = nmap.nmap_disable_dns(hostname, args="-oN DisableDNS")
                os.system("cat DisableDNS ; rm DisableDNS")
            else:
                remove()
    #[4] Scan Techniques
    if answer == "4":
        ask4 = input("\nConfigure Nmap Scan Techniques: \n   [1] TCP Scan (-sT) \n   [2] UDP Scan (-sU) \n   [3] SYN Scan (-sS) \n   [4] Ping Scan (-sP) \n   [5] Fin Scan (-sF) \n   [6] Idle Scan (-sL) \n   [q] Quit Scan \n   Enter a number: ")
        if ask4 == "q":
            remove()
        if ask4 == "1":
            print('\n---------------------------------------------')
            print("\nTCP Scan (-sT) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapScanTechniques()
            print('\n------------------------------------------------')
            save() 
            if file == "y":
                print('\n-----------------------------------------------')
                results = nmap.nmap_tcp_scan(hostname, args = "-T4 -oN TCPScan")
                print("The output has been saved to the file TCPScan.")
                os.system("cat TCPScan")
            elif file == "n":
                results = nmap.nmap_tcp_scan(hostname, args = "-T4 -oN TCPScan")
                os.system("cat TCPScan ; rm TCPScan")
            else:
                raise ValueError
        elif ask4 == "2":
            print('\n------------------------------------------------')
            print("\nUDP Scan (-sU) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapScanTechniques()
            print('\n--------------------------------------------------')
            save() 
            if file == "y":
                print('\n--------------------------------------------')
                results = nmap.nmap_udp_scan(hostname, args = "-T4 -oN UDPScan")
                print("The output has been saved to the file UDPScan.")
                os.system("cat UDPScan")
            elif file == "n":
                results = nmap.nmap_udp_scan(hostname, args = "-T4 -oN UDPScan")
                os.system("cat UDPScan ; rm UDPScan")
            else:
                raise ValueError
        elif ask4 == "3":
            print('\n------------------------------------------------')
            print("\nSYN Scan (-sS) ")
            hostname = input("Enter the target's IP Address or domain: ")
            nmap = nmap3.NmapScanTechniques()
            print('\n-------------------------------------------------')
            save() 
            if file == "y":
                print('\n--------------------------------------------')
                results = nmap.nmap_syn_scan(hostname, args = "-T4 -oN SYNScan")
                print("The output has been saved to the file SYNScan.")
                os.system("cat SYNScan")
            elif file == "n":
                results = nmap.nmap_syn_scan(hostname, args = "-T4 -oN SYNScan")
                os.system("cat SYNScan ; rm SYNScan")
            else:
                raise ValueError
        elif ask4 == "4":
            print('\n-------------------------------------------')
            print("\nPing Scan (-sP) ")
            hostname = input("Enter the target's IP Address or domain:  ")
            nmap = nmap3.NmapScanTechniques()
            print('\n--------------------------------------------')
            save() 
            if file == "y":
                print('\n--------------------------------------------')
                results = nmap.nmap_ping_scan(hostname, args = "-T4 -oN PingScan")
                os.system("cat PingScan")
                print("The output has been saved to the file PingScan.")
            elif file == "n":
                results = nmap.nmap_ping_scan(hostname, args = "-T4 -oN PingScan")
                os.system("cat PingScan ; rm PingScan")
            else:
                raise ValueError
        elif ask4 == "5":
            print('\n-------------------------------------------')
            print("\nFIN Scan (-sF) ")
            hostname = input("Enter the target's IP Address or domain:  ")
            nmap = nmap3.NmapScanTechniques()
            print('\n--------------------------------------------')
            save() 
            if file == "y":
                print('\n--------------------------------------------')
                results = nmap.nmap_fin_scan(hostname, args = "-T4 -oN FINScan")
                print("The output has been saved to the file FINScan.")
                os.system("cat FINScan")
            elif file == "n":
                results = nmap.nmap_fin_scan(hostname, args = "-T4 -oN FINScan")
                os.system("cat FINScan ; rm FINScan")
            else:
                raise ValueError
        elif ask4 == "6":
            print('\n-------------------------------------------')
            print("\nIdle Scan (-sL) ")
            hostname = input("Enter the target's IP Address or domain:  ")
            if hostname == "q":
                remove()
            nmap = nmap3.NmapScanTechniques()
            print('\n--------------------------------------------')
            save()
            if file == "y":
                print('\n--------------------------------------------')
                results = nmap.nmap_idle_scan(hostname, args = "-T4 -oN IdleScan")
                print("The output has been saved to the file IdleScan.")
                os.system("cat IdleScan")
            elif file == "n":
                results = nmap.nmap_idle_scan(hostname, args = "-T4 -oN IdleScan")
                os.system("cat IdleScan ; rm IdleScan")
            else:
                raise ValueError
#[5] Exit
    if answer == "5":
        raise KeyboardInterrupt
except KeyboardInterrupt:
    print("\nGoodbye...")
except ValueError:
    print("Make sure to follow instructions.")


