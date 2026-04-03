
import argparse
import os
import sys
import subprocess
import ipaddress
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from datetime import datetime

def process_pcap_info(file_name):

    # Open files to store results
    sdPtr=open(sdFile,'w')
    sPtr=open(sFile,'w')
    pPtr=open(pFile,'w')
    vPtr=open(vFile,'w')
    aPtr=open(aFile,'w')
    uPtr=open(uFile,'w')
    oPtr=open(oFile,'w')

    # Filter non IPv4/TCP packets
    print('Opening {}...'.format(file_name))
    start_time=datetime.now()

    count = 0
    interesting_packet_count = 0
    frameSize = 0
    link_offset = 0x1d
    len_offset = 0x26
    tecm_offset = 0x2a

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

      count += 1

      inter_id = pkt_data[link_offset]
      if inter_id != link: # 0x06: #0x08: #0x0a #0x0c
          # disregard other interface
          continue

      pkt_len = int.from_bytes(pkt_data[len_offset:len_offset+2],"big")
      tecm_data = pkt_data[tecm_offset:]  # strip tecm packet
      ether_pkt = Ether(tecm_data)
      pkt_payload = ether_pkt.payload
      time_stamp = (datetime.now()-start_time).total_seconds()

      try:

        # IPV4 Protocol
        if pkt_payload.type == 0x0800:
            #print('IPV4 Protocol')
            byte_ptr = 0x1b

            if (tecm_data[byte_ptr]==0x11):     # UDP
                #print("UDP")
                byte_ptr += 3
                ip_add=tecm_data[byte_ptr:byte_ptr+4]
                src_add=ipaddress.IPv4Address(ip_add)
                byte_ptr += 4
                ip_add=tecm_data[byte_ptr:byte_ptr+4]
                dst_add=ipaddress.IPv4Address(ip_add)
                byte_ptr += 4
                src_port=int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
                byte_ptr += 2
                dst_port=int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
                byte_ptr += 2
                payload_size=int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")-8

                # SomeIP Protocol => port 30490, 30491, 30500 or 30501
                if (src_port in [30490, 30491, 30500, 30501]) or (dst_port in [30490, 30491, 30500, 30501]):
                    byte_ptr += 4
                    serviceIdx = byte_ptr
                    serviceID = tecm_data[byte_ptr:byte_ptr+2].hex()
                    byte_ptr += 2
                    methodID = int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
                    byte_ptr += 2
                    pSize = int.from_bytes(tecm_data[byte_ptr:byte_ptr+4],"big")
                    byte_ptr += 10
                    msgType = tecm_data[byte_ptr]

                    serviceID_ptr = 0
                    while (serviceID_ptr < payload_size):
                        prn_str=str(time_stamp)+"s Link: "+str(link)

                        # SomeIP-SD Protocol
                        if (serviceID=="ffff" and methodID==0x8100):
                            byte_ptr += 6
                            eSize = int.from_bytes(tecm_data[byte_ptr:byte_ptr+4],"big")
                            prn_str += ", SOME/IP-SD, Src: "+str(src_add)+", Dst: "+str(dst_add)+", Size: "+str(eSize)
                            print(prn_str)
                            print(prn_str, file=sdPtr)

                            byte_ptr += 4
                            entry_ptr = 0
                            while (entry_ptr < eSize):
                                eType = tecm_data[byte_ptr]
                                byte_ptr += 4
                                eService =tecm_data[byte_ptr:byte_ptr+2].hex()
                                byte_ptr += 2
                                eInstance = int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
                                byte_ptr += 2
                                eVersion = tecm_data[byte_ptr]
                                byte_ptr += 1
                                eTTL = int.from_bytes(tecm_data[byte_ptr:byte_ptr+3],"big")
                                prn_str="  eType: "+str(eType)+", eService: 0x"+str(eService)+", eInstance: "+str(eInstance)+", eVersion: "+str(eVersion)+", eTTL: "+str(eTTL)
                                print(prn_str)
                                print(prn_str, file=sdPtr)
                                byte_ptr += 7
                                entry_ptr = entry_ptr + 16;

                        # SomeIP Service Protocol
                        else:
                            prn_str+=", SOME/IP Service: 0x"+str(serviceID)+", Method: "+str(methodID)+", Type: "+str(msgType)+", Size: "+str(pSize)
                            print(prn_str)
                            print(prn_str, file=sPtr)

                        serviceID_ptr += pSize+8;
                        if (serviceID_ptr<payload_size):
                            byte_ptr = serviceIdx + serviceID_ptr;
                            serviceID = tecm_data[byte_ptr:byte_ptr+2].hex()
                            byte_ptr += 2
                            methodID = int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
                            byte_ptr += 2
                            pSize = int.from_bytes(tecm_data[byte_ptr:byte_ptr+4],"big")
                            byte_ptr += 10
                            msgType = tecm_data[byte_ptr]

        # ARP Protocol
        elif pkt_payload.type == 0x0806:
            print('ARP Protocol')
            byte_ptr = 0x18
            opcode=int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
            byte_ptr += 8
            ip_add=tecm_data[byte_ptr:byte_ptr+4]
            snd_add=ipaddress.IPv4Address(ip_add)
            byte_ptr += 6
            ip_add=tecm_data[byte_ptr:byte_ptr+4]
            tgt_add=ipaddress.IPv4Address(ip_add)
            prn_str=str(time_stamp)+"s Link: "+str(link)+", ARP, Size: "+str(pkt_len)+", Opcode: "+str(opcode)+" Sender: "+str(snd_add)+" Target: "+str(tgt_add)
            print(prn_str)
            print(prn_str, file=aPtr)

        # AVTP Protocol
        elif pkt_payload.type == 0x88b5:
            #print('IPV4 Protocol')
            byte_ptr = 0x26
            videoPktSize=int.from_bytes(tecm_data[byte_ptr:byte_ptr+2],"big")
            byte_ptr = 0x2a
            if tecm_data[byte_ptr:byte_ptr+2] == b'\xff\xd8':
                frameSize=0
                vPktNum=0
            frameSize += videoPktSize
            vPktNum+=1
            byte_ptr+= videoPktSize - 2                # Last 2 bytes
            if tecm_data[byte_ptr:byte_ptr+2] == b'\xff\xd9':
                #metadata of video frame
                prn_str=str(time_stamp)+"s Link: "+str(link)+", AVTP, Frame Size: "+str(frameSize)+", Frame Packets: "+str(vPktNum)
                print(prn_str)
                print(prn_str, file=vPtr)

        # PTPv2 Protocol
        elif pkt_payload.type == 0x88f7:
            #print('PTPv2 Protocol')
            byte_ptr = 0x1a
            correctionField=int.from_bytes(tecm_data[byte_ptr:byte_ptr+8],"big")
            byte_ptr += 12
            ClockIdentity=tecm_data[byte_ptr:byte_ptr+8].hex()
            byte_ptr += 12
            controlField=tecm_data[byte_ptr]
            byte_ptr += 2
            precision_s=int.from_bytes(tecm_data[byte_ptr:byte_ptr+6],"big")
            byte_ptr += 6
            precision_ns=int.from_bytes(tecm_data[byte_ptr:byte_ptr+6],"big")
            prn_str=str(time_stamp)+"s Link: "+str(link)+", PTPv2, Size: "+str(pkt_len)+", Correction: "+str(correctionField)+" Identity: "+str(ClockIdentity)+" Control: "+str(controlField)+", Precision_s: "+str(precision_s)+", Precision_ns: "+str(precision_ns)
            print(prn_str)
            print(prn_str, file=pPtr)

        ## Protocol doesn't match
        else:
            #print('Unknown Protocol')
            prn_str=str(time_stamp)+"s Link: "+str(link)+", Unknown, Size: "+str(pkt_len)
            print(prn_str)
            print(prn_str, file=oPtr)

        interesting_packet_count += 1

      except:
          pass

    # close File
    sdPtr.close()
    sPtr.close()
    pPtr.close()
    vPtr.close()
    aPtr.close()
    uPtr.close()
    oPtr.close()

    # pcap processing statistics
    print('{} contains {} packets ({} interesting packets in link {})'.
          format(file_name, count, interesting_packet_count, link))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--link', type=int, metavar='<link id>',
                        help='camera link id', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    link = args.link
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    # output
    info_dir = "./ProInfo/"
    os.makedirs(info_dir, exist_ok=True)
    sdFile = info_dir+"someIP-SD.txt"
    sFile = info_dir+"someIP.txt"
    pFile = info_dir+"ptpV2.txt"
    vFile = info_dir+"avtp.txt"
    aFile = info_dir+"arp.txt"
    uFile = info_dir+"udp.txt"
    oFile = info_dir+"others.txt"

    # start pcap file
    process_pcap_info(file_name)
    sys.exit(0)
