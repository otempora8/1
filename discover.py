import socket
import struct

MULTICAST_GROUP = '239.255.102.18'
DISCOVERY_PORT = 50001  # 50001-50003

def listen_anydesk_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', DISCOVERY_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
    print(f"Listening AnyDesk messages on {MULTICAST_GROUP}:{DISCOVERY_PORT}...")
    
    while True:
        data, addr = sock.recvfrom(4096)
        ip_address = addr[0]

        try:
            decoded = data.decode('utf-8', errors='ignore')
            os_info = "Unknown"
            
            if "Windows" in decoded or "win" in decoded:
                os_info = "Windows"
            elif "mac" in decoded or "darwin" in decoded:
                os_info = "macOS"
            elif "linux" in decoded or "x11" in decoded:
                os_info = "Linux"
            elif "android" in decoded:
                os_info = "Android"
                
            print(f"DISCOVERED: IP={ip_address}, OS={os_info}")
            print(f"Packet length: {len(data)} байт")
            print("-" * 40)
            
        except Exception as e:
            print(f"Error while parsing packet from {ip_address}: {e}")

if __name__ == "__main__":
    listen_anydesk_discovery()
