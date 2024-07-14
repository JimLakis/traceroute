## Author: Jim Lakis

from threading import Thread, Lock

## scapy==2.5.0
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, TCP

import signal
import sys
import time


lock = Lock()

def make_ip_packet(dst: str = "www.Google.com", ttl: tuple = (1), *args, **kwargs):
    try:
        ip_packet = IP(dst=dst, ttl=ttl)
    except Exception as e:
        print(f"An error occurred creating the IP packet: {e}")
    return ip_packet

def make_tcp_packet(sport: int = 80, dport: int = 80, flags: int = 0x2, *args, **kwargs):
    try:
        tcp_packet = TCP(sport=sport, dport=dport, flags=flags)
    except Exception as e:
        print(f"An error occurred creating the TCP packet: {e}")
    return tcp_packet

def signal_handler(sig, frame):
    print("\nUser forced a quit...")
    sys.exit(0)

def perform_single_ttl_traceroute(ip_packet, tcp_packet, timeout: int = 5, *args, **kwargs):
    with lock:
        start_time = time.time()
        response = None
        while time.time() - start_time < timeout:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                break
            try:
                response = sr1(ip_packet / tcp_packet, timeout=min(1, remaining_time), verbose=False)
            except Exception as e:
                print(f"An unexpected error occurred when running the sr1() function: {e}")

            if response is not None:
                break
        print(response)
        return response


def main():
    '''Theads on YouTube
    ## https://www.youtube.com/watch?v=m70_u0DPK5k
    '''
    threads = []

    tcp_packet = make_tcp_packet()
    for i in range(4):
        ip_packet = make_ip_packet(ttl=i)
        single_thread = Thread(target=perform_single_ttl_traceroute, args=(ip_packet, tcp_packet))
        threads.append(single_thread)
        single_thread.start()

    for t in threads:
        t.join()

    for i in threads:
        print(i)

if __name__ == "__main__":
    print(f"Starting traceroute... enter 'ctrl+c' to force quit\n")
    signal.signal(signal.SIGINT, signal_handler)
    main()
