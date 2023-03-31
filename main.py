# Zdar
# Discovery
# Advanced
# Reconnaissance

ZDAR_INTERVAL = 5
ZDAR_ALIAS = "example"
ZDAR_VERSION = 3



import socket
import select 
import time
import platform
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

zdar_db = []

time_delay = time.time() + ZDAR_INTERVAL

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def handle_packet(data, ip):
    if data[0:4] != b"ZDAR": return

    version = int.from_bytes(data[4:6], "little", signed=False)

    interval = int.from_bytes(data[6:8], "little", signed=False)
    print(interval)

    hostname_len = int.from_bytes(data[8:10], "little", signed=False)
    hostname = data[10:10+hostname_len].decode("utf-8")
    print(hostname)
    
    alias_len = int.from_bytes(data[10+hostname_len:12+hostname_len], "little", signed=False)
    alias = data[12+hostname_len:12+hostname_len+alias_len].decode("utf-8")
    print(alias)
    
    plat_len = int.from_bytes(data[12+hostname_len:14+hostname_len+alias_len], "little", signed=False)
    plat = data[14+hostname_len+alias_len:14+hostname_len+alias_len+plat_len].decode("utf-8")
    print(plat)

    is_in = False
    for item in zdar_db:
        if item["hostname"] == hostname:     
            item["hostname"] = hostname
            item["zdar_version"] = version
            item["zdar_interval"] = interval
            item["alias"] = alias
            item["last_seen"] = time.time()
            item["platform"] = plat
            item["ip"] = ip[0]
            is_in = True
            break

    if not is_in:
        i = {}
        i["hostname"] = hostname
        i["zdar_version"] = version
        i["zdar_interval"] = interval
        i["alias"] = alias
        i["last_seen"] = time.time()
        i["platform"] = plat
        i["ip"] = ip[0]
        zdar_db.append(i)

def print_item(item, dead=False):
    """     
    message = item["hostname"] + "\t" 
    message += item["alias"] + "\t" 
    
    message += str(item["zdar_version"]) 
    if ZDAR_VERSION != item["zdar_version"]:
        message +="!\t\t"
    else:
        message += "\t\t"
    
    message += str(round(time.time() - item["last_seen"])) + "s" + "\t\t"
    message += str(item["zdar_interval"]) + "s" + "\t\t"
    message += item["platform"] + "\t"
    if dead:
        message += "DYING!"
    
    print(message)
    """

    print("\t",item["ip"] + "\t", '"'+item['alias'] +'"', item["hostname"])
    print("\t","└ Last seen:", str(round(time.time() - item["last_seen"])) + "s")
    print("\t","└ Version:", item["zdar_version"], "!" if ZDAR_VERSION != item["zdar_version"] else "")
    print("\t","└ ZDAR interval:", str(item["zdar_interval"]) + "s")
    print("\t","└ Platform:", item["platform"])
    if dead:
        print("\t","└ Dead interval exceeded! Removing...")
    print()

def print_output(sending):
    clear()
    print(""" 
    ███████╗██████╗  █████╗ ██████╗ 
    ╚══███╔╝██╔══██╗██╔══██╗██╔══██╗
      ███╔╝ ██║  ██║███████║██████╔╝
     ███╔╝  ██║  ██║██╔══██║██╔══██╗
    ███████╗██████╔╝██║  ██║██║  ██║
    ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                                  
    """)
    print("Version:",ZDAR_VERSION)
    print("Local ZDAR interval:", ZDAR_INTERVAL)
    print("Local alias:", ZDAR_ALIAS)
    if sending:
        print("Status: Sending ZDAR ")
    else: 
        print("Status: Listening")

    print("\nDiscovered:\n")
    print("\t IP address\t \"Alias\" Hostname\n")
    for item in zdar_db:
        if (item["last_seen"] + item["zdar_interval"] * 2) < time.time():
            print_item(item, dead=True)
            zdar_db.remove(item)
        else:
            print_item(item)
    
    if sending:
        time.sleep(1)

def send_zdar():
    hostname = socket.gethostname()
    # Header
    packet_data = b"ZDAR"
    
    # Version
    packet_data += int.to_bytes(ZDAR_VERSION, 2, "little", signed=False)

    # Zdar interval
    packet_data += int.to_bytes(ZDAR_INTERVAL, 2, "little", signed=False)
    
    # Hostname
    packet_data += int.to_bytes(len(hostname), 2, "little", signed=False) 
    packet_data += socket.gethostname().encode("utf-8")
    
    # Alias
    packet_data += int.to_bytes(len(ZDAR_ALIAS), 2, "little", signed=False)
    packet_data += ZDAR_ALIAS.encode("utf-8")
    
    # Platform
    plat = platform.platform()
    packet_data += int.to_bytes(len(plat), 2, "little", signed=False)
    packet_data += plat.encode("utf-8")
    
    sock.sendto(packet_data, ("255.255.255.255", 10069))


if __name__ == "__main__":
    send_zdar()
    while True:
        sending = False
        rede, wride, execude = select.select([sock], [], [], 1)

        if len(rede) > 0:
            data, ip = sock.recvfrom(1024)
            handle_packet(data, ip)

        if time.time() > time_delay:
            sending = True
            time_delay = time.time() + ZDAR_INTERVAL
            send_zdar()


        print_output(sending)
