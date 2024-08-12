/*
 * (C) 2003-23 - ntop 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>

#include "pfring.h"
#include "pfutils.c"

#define MAX_PKT_LEN 1536

u_int32_t num_sent = 0;

FILE *sPtr, *sdPtr, *pPtr, *vPtr, *aPtr, *uPtr, *oPtr;
int write_to_file=1, num_pkts=0, frameSize=0, vPktNum=0;
double start=0; 
float max_duration=0;

/* ****************************************************** */

void printHelp(void) {
  printf("pfProInfo - Receives traffic from -a device using vanilla PF_RING\n\n");
  printf("-h              [Print help]\n");
  printf("-p              [Use pfring_send() instead of bridge]\n");
  printf("-a <device>     [Camera device name]\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-w <watermark>  Watermark\n");
}

/* ******************************** */

void my_sigalarm(int sig) {
  char buf[32];

  pfring_format_numbers((double)num_sent, buf, sizeof(buf), 0),
  printf("%s pps\n", buf);
  num_sent = 0;
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

u_int pktBytes(u_char *pkt, int startIdx, int numBytes) {
  int stopIdx = startIdx + numBytes-1;
  u_int data = pkt[startIdx];
  int i;

  for (i = startIdx; i < stopIdx; ++i)
  {
      data = pkt[i+1] + (data << 8);
  }
  return(data);
}

/* Process the link's packet into separate protocols and save it to separate files */
void linkPkt(int i1, int i2, u_char *rcv_pkt, u_int pkt_len) {
  u_int linkID, ubytes, ubytes1, payload_size=0, serviceID, methodID, pSize, msgType;
  u_int eSize, eType, eService, eInstance, eVersion, eTTL;
  u_int opcode, srcID, destID, senderID, targetID;
  int byte_ptr, serviceIdx, serviceID_ptr, entry_ptr;
  int videoPktSize;
  float time_stamp;
  struct timespec now;
  int tecm_offset = 0x2a;

  byte_ptr = 0x1a;
  linkID = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);               // Capture module interface?
  
  if ((linkID==i1) || (linkID==i2) || (i1==0)) {                    // Selected AE link
    byte_ptr = tecm_offset + 0x10;                          
    ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);             // Protocol?
    clock_gettime(CLOCK_REALTIME, &now);
    time_stamp = (now.tv_sec + (now.tv_nsec/1000000000.0)) - start;

    /* save different protocol into separate files */
    switch(ubytes)
    {       
      /* IPV4 Protocol */
      case 0x0800:
        num_pkts++;
        byte_ptr = tecm_offset + 0x1b;
        if (rcv_pkt[byte_ptr]==0x11) {   // UDP
          byte_ptr = tecm_offset + 0x21;
          srcID = rcv_pkt[byte_ptr];                                // src address ID
          byte_ptr += 4;                          
          destID = rcv_pkt[byte_ptr];                               // dest address ID
          byte_ptr += 1;                          
          ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);       // src port
          byte_ptr += 2;                          
          ubytes1 = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);      // dst port
          byte_ptr += 2;                          
          payload_size = pktBytes((u_char *) rcv_pkt, byte_ptr, 2) - 8;

          /* SomeIP Protocol => port 30490, 30491, 30500 or 30501 */   
          if (ubytes==30490 || ubytes==30491 || ubytes==30500 || ubytes==30501 || ubytes1==30490 || ubytes1==30491 ||ubytes1==30500 || ubytes1==30501) { 
              byte_ptr += 4;    
              serviceIdx = byte_ptr;                      
              serviceID = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
              byte_ptr += 2;                          
              methodID = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
              byte_ptr += 2;                          
              pSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);
              byte_ptr += 10;
              msgType = rcv_pkt[byte_ptr];

              serviceID_ptr = 0;
              while (serviceID_ptr < payload_size) {
                printf("Link: %i, ", linkID);
                if (serviceID==0xffff && methodID==0x8100) {        // SomeIP-SD Protocol
                  byte_ptr += 6;                          
                  eSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);
                  byte_ptr += 4;
                  printf("SOME/IP-SD, Src: %i, Dest: %i, Size: %i\n", srcID, destID, eSize);
                  entry_ptr = 0;
                  while (entry_ptr < eSize) {
                    eType = rcv_pkt[byte_ptr];
                    byte_ptr += 4;
                    eService = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                    byte_ptr += 2;
                    eInstance = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                    byte_ptr += 2;
                    eVersion = rcv_pkt[byte_ptr];
                    byte_ptr += 1;
                    eTTL = pktBytes((u_char *) rcv_pkt, byte_ptr, 3);
                    printf("  eType: %i, eService: %x, eInstance: %x, eVersion: %i, eTTL: %i\n", eType, eService, eInstance, eVersion, eTTL);
                    if (write_to_file==1) {  
                      fprintf(sdPtr, "%i, %f, %i, %i, %i, %i, %x, %x, %i, %i\n", num_pkts, time_stamp, linkID, srcID, destID, eType, eService, eInstance, eVersion, eTTL);
                    }
                    byte_ptr += 7;
                    entry_ptr = entry_ptr + 16;
                  }                    
                }
                else {                                              // SomeIP Service Protocol
                  printf("SOME/IP Service: %x, Method: %x, Type: %i, Size: %i\n", serviceID, methodID, msgType, pSize);
                  if (write_to_file==1) {
                    fprintf(sPtr, "%i, %f, %i, %i, %i, %x, %x, %i, %i\n", num_pkts, time_stamp, linkID, srcID, destID, serviceID, methodID, msgType, pSize);
                  }
                }

                serviceID_ptr += pSize+8;
                if (serviceID_ptr<payload_size) {
                  byte_ptr = serviceIdx + serviceID_ptr;
                  serviceID = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                  byte_ptr += 2;                          
                  methodID = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                  byte_ptr += 2;                          
                  pSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);
                  byte_ptr += 10;
                  msgType = rcv_pkt[byte_ptr];
                }
              }
            }
            else { // other UDP messages
              printf("Link:%i, UDP, Size: %i, Src: %i, Dest: %i, Src Port: %i, Dst Port: %i\n", linkID, pkt_len, srcID, destID, ubytes, ubytes1);
              if (write_to_file==1) {
                fprintf(uPtr, "%i, %f, %i, %i, %i, %i, %i, %i\n", num_pkts, time_stamp, linkID, pkt_len, srcID, destID, ubytes, ubytes1);
              }
            }
        }

        /* IPV4 - TCP Protocol */
        else { 
          byte_ptr = tecm_offset + 0x21;
          srcID = rcv_pkt[byte_ptr];                                  // src address ID
          byte_ptr += 4;                          
          destID = rcv_pkt[byte_ptr];                                 // dest address ID
          printf("Link:%i, IPV4, Size: %i, Src: %i, Dest: %i\n", linkID, pkt_len, srcID, destID);
          if (write_to_file==1) {
            fprintf(oPtr, "%i, %f, %i, IPV4, %i, %i, %i\n", num_pkts, time_stamp, linkID, pkt_len, srcID, destID);
          }
        }
        break;

      /* ARP Protocol */
      case 0x0806:
        num_pkts++;
        byte_ptr += 8;
        opcode = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);         // src port?
        byte_ptr += 11;
        senderID = rcv_pkt[byte_ptr];
        byte_ptr += 10;
        targetID = rcv_pkt[byte_ptr];
        printf("Link: %i, ARP, Size: %i, Opcode: %i, Sender: %i, Target: %i\n", linkID, pkt_len, opcode, senderID, targetID);
        if (write_to_file==1) {
          fprintf(aPtr, "%i, %f, %i, %i, %i, %i, %i\n", num_pkts, time_stamp, linkID, pkt_len, opcode, senderID, targetID);
        }
        break;

      /* AVTP Protocl */
      case 0x88b5:
        if ((i1==0) && (linkID!=6)) break;                    // for all links, only capture Fcam

        byte_ptr = tecm_offset + 0x26;                        // Pkt size?
        videoPktSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
        byte_ptr = tecm_offset + 0x2a;                        // First 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);   // First 2 bytes
        if (ubytes==0xffd8) {                                 // Start of video frame
          frameSize=0;
          vPktNum=0;
        } 
        frameSize += videoPktSize;
        vPktNum += 1;
        ubytes1 = byte_ptr + videoPktSize - 2;                // Last 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, ubytes1, 2);    // Last 2 bytes
        if (ubytes==0xffd9) {                                 // End of video frame
          // only save metadata of Fcam video frame
          num_pkts++;
          printf("Link: %i, AVTP, Frame Size: %i, vPktNum: %i\n", linkID, frameSize, vPktNum);
          if (write_to_file==1) {
            fprintf(vPtr, "%i, %f, %i, %i, %i\n", num_pkts, time_stamp, linkID, frameSize, vPktNum);
          }
        }
        break;

      /* PTPv2 Protocol */
      case 0x88f7:
        num_pkts++;
        byte_ptr = tecm_offset + 0x1a;
        uint correctionField = pktBytes((u_char *) rcv_pkt, byte_ptr, 6);
        byte_ptr = tecm_offset + 0x26;
        uint ClockIdentity = pktBytes((u_char *) rcv_pkt, byte_ptr, 8);
        byte_ptr = tecm_offset + 0x32;
        uint controlField = rcv_pkt[byte_ptr];
        byte_ptr += 2;
        uint precision_s = pktBytes((u_char *) rcv_pkt, byte_ptr, 6);
        byte_ptr += 6;
        uint precision_ns = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);
        printf("Link: %i, PTPv2, Size: %i, Correction: %i, Identity: %x, Control: %i, Precision_s: %i, Precision_ns: %i\n", linkID, pkt_len,\
         correctionField, ClockIdentity, controlField, precision_s, precision_ns);
        if (write_to_file==1) {
          fprintf(pPtr, "%i, %f, %i, %i, %i, %x, %i, %i, %i\n", num_pkts, time_stamp, linkID, pkt_len, correctionField, ClockIdentity, \
          controlField, precision_s, precision_ns);
        }
        break;

      // protocol doesn't match
      default:
        byte_ptr = tecm_offset + 0x21;
        srcID = rcv_pkt[byte_ptr];                                  // src address ID
        byte_ptr += 4;                          
        destID = rcv_pkt[byte_ptr];                                 // dest address ID
        printf("Link:%i, Unknown: %x, Size: %i, Src: %i, Dest: %i\n", linkID, ubytes, pkt_len, srcID, destID);
        if (write_to_file==1) {
          fprintf(oPtr, "%i, %f, %i, %x, %i, %i, %i\n", num_pkts, time_stamp, linkID, ubytes, pkt_len, srcID, destID);
        }
    }

    if (write_to_file==1) {
      // printf("%i, %i, %f, %f\n", now.tv_sec, now.tv_nsec, time_stamp, start);
      if (time_stamp >= max_duration) {
        write_to_file = 0;
        fclose(sdPtr);
        fclose(sPtr);
        fclose(pPtr);
        fclose(vPtr);
        fclose(aPtr);
        fclose(uPtr);
        fclose(oPtr);
        printf("Files are closed! <=====================================================================\n");
        exit(0);
      }
    }
  }
}

/* ****************************************************** */

int main(int argc, char* argv[]) {
  pfring *a_ring;
  char *a_dev = NULL, c;
  u_int8_t use_pfring_send = 0;
  int a_ifindex;
  int bind_core = -1;
  u_int16_t watermark = 1;
  char *bpfFilter = NULL;

  int AE_link, iface1, iface2, firstTime=1;
  struct timespec startClk;

  while((c = getopt(argc,argv, "ha:b:c:f:vpg:w:")) != -1) {
    switch(c) {
      case 'h':
        printHelp();
        return 0;
        break;
      case 'a':
        a_dev = strdup(optarg);
        break;
      case 'f':
        bpfFilter = strdup(optarg);
        break;
      case 'p':
        use_pfring_send = 1;
        break;
      case 'g':
        bind_core = atoi(optarg);
        break;
      case 'w':
        watermark = atoi(optarg);
        break;
    }
  }  

  if (!a_dev) {
    printf("You must specify one device!\n");
    return -1;
  }

  /* Device A */
  if((a_ring = pfring_open(a_dev, MAX_PKT_LEN, 
                 PF_RING_PROMISC |
                 PF_RING_LONG_HEADER |
                 PF_RING_DISCARD_INJECTED_PKTS |
                 (use_pfring_send ? 0 : PF_RING_RX_PACKET_BOUNCE))
    ) == NULL) {
    printf("pfring_open error for %s [%s]\n", a_dev, strerror(errno));
    return(-1);
  }

  pfring_set_application_name(a_ring, "pfbridge-a");
  pfring_set_direction(a_ring, rx_only_direction);
  pfring_set_socket_mode(a_ring, recv_only_mode);
  pfring_set_poll_watermark(a_ring, watermark);
  pfring_get_bound_device_ifindex(a_ring, &a_ifindex);

  /* Adding BPF filter */
  if(bpfFilter != NULL) {
    int rc = pfring_set_bpf_filter(a_ring, bpfFilter);
    if(rc != 0)
      printf("pfring_set_bpf_filter(%s) returned %d\n", bpfFilter, rc);
    else
      printf("Successfully set BPF filter '%s'\n", bpfFilter);
  }
 
  /* Enable Sockets */

  if (pfring_enable_ring(a_ring) != 0) {
    printf("Unable enabling ring 'a' :-(\n");
    pfring_close(a_ring);
    return(-1);
  }

  /* Process protocols from selected link or all links */
  printf("1=HU<->BDC,   2=TSR<->BDC,  3=TSR<->Fcam\n");
  printf("4=TSR<->Dcam, 5=TSR<->Pcam, 6=TSR<->Rcam\n");
  printf("0=All links\n");
  printf("Select AE link: ");
  scanf("%i", &AE_link);
  printf("max_duration (sec): ");
  scanf("%f", &max_duration);

  switch (AE_link) {
    case 0:
        iface1 = 0;
        iface2 = 0;
        break;
    case 1:
        iface1 = 1;
        iface2 = 2;
        break;
    case 2:
        iface1 = 3;
        iface2 = 4;
        break;
    case 3:
        iface1 = 5;
        iface2 = 6;
        break;
    case 4:
        iface1 = 7;
        iface2 = 8;
        break;
    case 5:
        iface1 = 9;
        iface2 = 10;
        break;
    case 6:
        iface1 = 11;
        iface2 = 12;
        break;
    default:
        exit(0);
        break;
  }

  if (write_to_file==1) {
    /* Saved files: - someIP.txt, someIP-SD.txt, ptpV2.tx, avtp.txt, arp.txt, udp.txt, others.txt */

    // someIP-SD
    sdPtr = fopen("/home/asset/AE_Scripts/data/someIP-SD.txt","w");
    if (sdPtr == NULL)
    {
      printf("someIP-SD File Error!");
      exit(1);             
    }
    fprintf(sdPtr, "num_pkts, time_stamp, linkID, srcID, destID, type, service (0x), instance (0x), ver, TTL\n");
    // someIP
    sPtr = fopen("/home/asset/AE_Scripts/data/someIP.txt","w");
    if (sPtr == NULL)
    {
      printf("someIP File Error!");
      exit(1);             
    }
    fprintf(sPtr, "num_pkts, time_stamp, linkID, srcID, destID, service (0x), method (0x), type, size\n");
    // PTPv2
    pPtr = fopen("/home/asset/AE_Scripts/data/ptpV2.txt","w");
    if (pPtr == NULL)
    {
      printf("PTPv2 File Error!");
      exit(1);             
    }
    fprintf(pPtr, "num_pkts, time_stamp, linkID, pkt_len, correctionField, ClockIdentity (0x), controlField, precision_s, precision_ns\n");
    // AVTP
    vPtr = fopen("/home/asset/AE_Scripts/data/avtp.txt","w");
    if (vPtr == NULL)
    {
      printf("video File Error!");
      exit(1);             
    }
    fprintf(vPtr, "num_pkts, time_stamp, linkID, frameSize, vPktNum\n");
    // ARP
    aPtr = fopen("/home/asset/AE_Scripts/data/arp.txt","w");
    if (aPtr == NULL)
    {
      printf("arp File Error!");
      exit(1);             
    }
    fprintf(aPtr, "num_pkts, time_stamp, linkID, len, opcode, senderID, targetID\n");
    // UDP
    uPtr = fopen("/home/asset/AE_Scripts/data/udp.txt","w");
    if (uPtr == NULL)
    {
      printf("udp File Error!");
      exit(1);             
    }
    fprintf(uPtr, "num_pkts, time_stamp, linkID, pkt_len, srcID, destID, srcPort, dstPort\n");
    // other protocols
    oPtr = fopen("/home/asset/AE_Scripts/data/others.txt","w");
    if (oPtr == NULL)
    {
      printf("others File Error!");
      exit(1);             
    }
    fprintf(oPtr, "num_pkts, time_stamp, linkID, protocol (0x), pkt_len, srcID, destID\n");
  }

  if(bind_core >= 0)
    bind2core(bind_core);

  printf("Capturing info...\n");
  while(1) {
    u_char *buffer;
    struct pfring_pkthdr hdr;
    
    if(pfring_recv(a_ring, &buffer, 0, &hdr, 1) > 0) {
      
      if(use_pfring_send) {
        if (firstTime==1) {
          clock_gettime(CLOCK_REALTIME, &startClk);
          start = startClk.tv_sec + (startClk.tv_nsec/1000000000.0);
          firstTime = 0;
        } 
        
        /* Process the link's packet into separate protocols and save it to separate files */
        linkPkt(iface1, iface2, (u_char *) buffer, hdr.caplen);
      }	
    }
  }

  pfring_close(a_ring);
  
  return(0);
}
