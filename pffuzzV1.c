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

/* ****************************************************** */

void printHelp(void) {
  printf("pffuzz - Forwards traffic from -a -> -b device using vanilla PF_RING\n\n");
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

u_int pktBytes(u_char *pkt, int start, int numBytes) {
  int stop = start + numBytes-1;
  u_int data = pkt[start];
  int i;

  for (i = start; i < stop; ++i)
  {
      data = pkt[i+1] + (data << 8);
  }
  return(data);
}

/* perform random fuzzing on SomeIP or PTP */
void fuzz(u_char *fuzz_pkt, u_int pkt_len) {
  u_int ubytes, ubytes1, serviceID, methodID, nextByteIdx, pduSize, msgType;
  int payloadSize, tgtByte, byte_before;
  int someip_fuzz_enable = 0;   // SomeIP fuzzing: 1 - enable, 0 - disable
  int ptp_fuzz_enable = 0;      // PTP fuzzing: 1 - enable, 0 - disable

  ubytes = pktBytes((u_char *) fuzz_pkt, 0x10, 2);
  switch(ubytes)
  {
    // IPV4
    case 0x0800:
      if (fuzz_pkt[0x1b]==0x11) {   // UDP
        ubytes = pktBytes((u_char *) fuzz_pkt, 0x26, 2);
        ubytes1 = pktBytes((u_char *) fuzz_pkt, 0x28, 2);

        // SOME/IP => port 30490 or 30501
        if (ubytes==30490 || ubytes==30501 || ubytes1==30490 || ubytes1==30501) {
          serviceID = pktBytes((u_char *) fuzz_pkt, 0x2e, 2);
          methodID = pktBytes((u_char *) fuzz_pkt, 0x30, 2);
          nextByteIdx = 0x32;
          pduSize = pktBytes((u_char *) fuzz_pkt, nextByteIdx, 4);
          nextByteIdx += 10;
          msgType = fuzz_pkt[nextByteIdx];
          if (serviceID==0xffff && methodID==0x8100) {              // SomeIP-SD
            printf("%i SOME/IP-SD\n", pkt_len);
            printf("  Service: %x Method: %x Size: %i Type: %x\n", serviceID, methodID, pduSize, msgType);
          }
          else {                                                    // SomeIP
            printf("%i SOME/IP\n", pkt_len);
            printf("  Service: %x Method: %x Size: %i Type: %x\n", serviceID, methodID, pduSize, msgType);
          }
          if (someip_fuzz_enable) {                                 // if fuzzing SomeIP         
            nextByteIdx += 2;
            payloadSize = pduSize - 8;
            if (payloadSize!=0) {
              tgtByte = nextByteIdx + (rand() % payloadSize);
              byte_before = fuzz_pkt[tgtByte];
              fuzz_pkt[tgtByte] = rand() % 256;
              printf("    Byte: %x Before: %x After: %x\n", tgtByte, byte_before, fuzz_pkt[tgtByte]);
            }
          }
        }
        else {
          printf("%i UDP\n", pkt_len);
        }
      }
      else {
        printf("%i IPV4\n", pkt_len);
      }
      break;

    // ARP
    case 0x0806:
      printf("%i ARP\n", pkt_len);
      break;

    // AVTP
    case 0x88b5:
      // printf("%i AVTP\n", pkt_len);
      break;

    // PTPv2
    case 0x88f7:
      uint correctionField = pktBytes((u_char *) fuzz_pkt, 0x1a, 6);
      uint ClockIdentity = pktBytes((u_char *) fuzz_pkt, 0x26, 8);
      ubytes = fuzz_pkt[0x32];
      switch(ubytes)
      {
        case 0x00:  // Sync Message
          printf("%i PTPv2 correctionFIeld=%i ClockIdentity=%i Sync\n", pkt_len, correctionField, ClockIdentity);
          break;

        case 0x02:  // Follow_Up Message
          printf("%i PTPv2 correctionFIeld=%i ClockIdentity=%i Follow_up\n", pkt_len, correctionField, ClockIdentity);
          if (ptp_fuzz_enable) {                                // if fuzz PTP
            uint origTS = pktBytes((u_char *) fuzz_pkt, 0x3a, 4);
            fuzz_pkt[0x3a] = rand() % 256;
            uint fuzzTS = pktBytes((u_char *) fuzz_pkt, 0x3a, 4);
            printf("  preciseOriginalTimestamp - Before=%i, After=%i\n", origTS,fuzzTS);
          }
          break;
        default:
            printf("%i Error! Not valid PTP protocol %x", pkt_len, ubytes);
      }
      break;

    // operator doesn't match
    default:
        printf("%i Error! Not valid protocol %x", pkt_len, ubytes);
  }

}

/* ****************************************************** */

int main(int argc, char* argv[]) {
  pfring *a_ring, *b_ring;
  char *a_dev = NULL, *b_dev = NULL, c;
  u_int8_t verbose = 0, use_pfring_send = 0;
  int a_ifindex, b_ifindex;
  int bind_core = -1;
  u_int16_t watermark = 1;
  char *bpfFilter = NULL;

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
    
    if(pfring_recv(a_ring, &buffer, 0, &hdr, 1) > 0) {
      int rc;
      
      if(use_pfring_send) {

        /* perform random fuzzing on SomeIP or PTP */
        fuzz((u_char *) buffer, hdr.caplen);
        rc = pfring_send(b_ring, (char *) buffer, hdr.caplen, 1);

        if(rc < 0)
          printf("pfring_send(caplen=%u <= l2+mtu(%u)?) error %d\n", hdr.caplen, pfring_get_mtu_size(b_ring), rc);
        else if(verbose)
          printf("Forwarded %d bytes packet\n", hdr.len);
      } else {

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
