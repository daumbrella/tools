# -*- coding: utf-8 -*-
"""
Created on Wed Jan  2 10:07:52 2019

@author: yayao
"""
from binascii import b2a_hex
import argparse
import sys
try:
    # https://github.com/KimiNewt/pyshark
    import pyshark
except ImportError:
    print("ERROR: can't import pyshark. pip3 install pyshark", file=sys.stderr)
    sys.exit(1)

#获取数据包源和目的mac地址
def get_macs(packet):
    if "eth" in packet:
        return (packet.eth.src, packet.eth.dst)
    elif "wlan" in packet:
        return (packet.wlan.ta, packet.wlan.addr)
    raise Exception("Cannot find a MAC address.")

#大小端转换
def conver_LE(str):
    bytes=bytearray.fromhex(str)
    str=b2a_hex(bytes[::-1])
    return str

#对数据包内的内容进行解析
def parse_packet_data(data):
    '''header_len=32
    optstr=conver_LE(data[8:12])
    optlen=int(optstr,16)
    #print (optlen)
    return data[header_len+optlen*2:]'''

def get_packets(pcapfile,filter_rules=None):
    if filter_rules is not None:
        cap = pyshark.FileCapture(pcapfile, display_filter=(filter_rules))
    else:
        cap = pyshark.FileCapture(pcapfile)
    return cap

def traverse_pcap(pcap,filter_rules):
    cap=get_packets(pcap,filter_rules=filter_rules)
    for packet in cap:
        if "data" not in packet:
            continue
        print (packet.data.data)

		
'''def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap",help="a pcap file from wireshark or tcpdump")
    parser.add_argument("--filter",default=None,help="a rule to filter packets such as 'udp'")
    #args=parser.parse_args(["pcap","","--filter",""])
    args=parser.parse_args()
    traverse_pcap(args.pcap,args.filter)

if __name__ == "__main__":
    main()'''