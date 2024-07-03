## scapy==2.5.0
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, TCP

import signal
import sys
import time


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
    return response


def main(responses):
    '''
    '''
    print(f"Starting traceroute... enter 'ctrl+c' to force quit\n")

    signal.signal(signal.SIGINT, signal_handler)

    try:
        tcp_packet = make_tcp_packet()
        i = 1
        while i <= 64:
            ip_packet = make_ip_packet(ttl=i)
            reply_packet = perform_single_ttl_traceroute(ip_packet, tcp_packet, timeout = 5)
            k = f"{str(i)}"
            print(f"ttl {k} complete")
            if isinstance(reply_packet, IP):
                #v = f"{str(reply_packet[IP].src)}"
                v = reply_packet
                if v in responses.values():
                    break
                else:
                    responses.update({k: v})
                    print(f"answering IP address {v}")
            else:
                print(f"Response is not an IP packet")
                break
            i+=1
    except Exception as e:
        print(f"An unexpected error occurred within the main() function: {e}")
    finally:
        return responses


if __name__ == "__main__":
    responses = {}
    main(responses)
    print(responses)
