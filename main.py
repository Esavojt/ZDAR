# Zdar
# Discovery
# Advanced
# Reconnaissance

ZDAR_INTERVAL = 5
ZDAR_ALIAS = "example"
ZDAR_VERSION = 3


ZDAR_PORT = 10069

import socket
import select 
import time
import platform
import os

# Setup socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", ZDAR_PORT))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

zdar_db = []

# Method for clearing the screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Method for handling packet data and creating entries
def handle_packet(data, ip):
    offset = 0
    if data[offset:offset + 4] != b"ZDAR": return
    offset += 4

    version = int.from_bytes(data[offset:offset + 2], "little", signed=False)
    offset += 2

    interval = int.from_bytes(data[offset:offset + 2], "little", signed=False)
    offset += 2

    hostname_len = int.from_bytes(data[offset:offset + 2], "little", signed=False)
    offset += 2
    hostname = data[offset:offset + hostname_len].decode("utf-8")
    offset += hostname_len
    
    alias_len = int.from_bytes(data[offset:offset + 2], "little", signed=False)
    offset += 2
    alias = data[offset:offset + alias_len].decode("utf-8")
    offset += alias_len
    
    plat_len = int.from_bytes(data[offset:offset + 2], "little", signed=False)
    offset += 2
    plat = data[offset:offset + plat_len].decode("utf-8")
    offset += plat_len

    is_in = False
    # Check if item is already in DB, if yes, update the entry, if not create a new one
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
    # Older method of showing entries
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

    # Newer method
    print("\t",item["ip"] + "\t", '"'+item['alias'] +'"', item["hostname"])
    print("\t"," └ Last seen:", str(round(time.time() - item["last_seen"])) + "s")
    if dead:
        print("\t","   └ Dead interval exceeded! Removing...")

    print("\t"," └ Version:", item["zdar_version"], "!" if ZDAR_VERSION != item["zdar_version"] else "")
    print("\t"," └ ZDAR interval:", str(item["zdar_interval"]) + "s")
    print("\t"," └ Platform:", item["platform"])
    print()

# A method to refresh and print the output to stdout
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
    # Update msg if sent packet 
    if sending:
        print("Status: Sending ZDAR ")
    else: 
        print("Status: Listening")

    print("\nDiscovered:\n")
    print("\t IP address\t \"Alias\" Hostname\n")

    # print every item to screen, if they surpassed the dead interval, delete them after 5 sec
    for item in zdar_db:
        if (item["last_seen"] + item["zdar_interval"] * 2) < time.time():
            print_item(item, dead=True)
            if (item["last_seen"] + item["zdar_interval"] * 2 + 5) < time.time():
                zdar_db.remove(item)
        else:
            print_item(item)

# Method to send ZDAR announcement packet
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
    
    # Send packet to broadcast
    sock.sendto(packet_data, ("255.255.255.255", ZDAR_PORT))

# Main code
if __name__ == "__main__":
    send_zdar()
    time_delay = time.time() + ZDAR_INTERVAL

    while True:
        sending = False
        # Check if announcement was received
        readable, _, _ = select.select([sock], [], [], 0)

        # If yes read data and handle them
        if len(readable) > 0:
            data, ip = sock.recvfrom(1024)
            handle_packet(data, ip)

        # If ZDAR_INTERVAL was already surpassed, send new packet
        if time.time() > time_delay:
            sending = True
            time_delay = time.time() + ZDAR_INTERVAL
            send_zdar()


        print_output(sending)
        time.sleep(0.5)
