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
int fIdx=0, dIdx=0, pIdx=0, rIdx=0;
// int fx=0, dx=1, px=2, rx=3;
u_char fFrame[1000000];
u_char dFrame[1000000];
u_char pFrame[1000000];
u_char rFrame[1000000];
FILE *fVideo, *dVideo, *pVideo, *rVideo;


/* ****************************************************** */

void printHelp(void) {
  printf("pf4Cam - Receives camera traffic from -a device using vanilla PF_RING\n\n");
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

/* Checking for camera AVTP messages and display video frame */
void cameraPkt(u_char *rcv_pkt, u_int pkt_len) {
  u_int ubytes, ubytes1, iface;
  int byte_ptr, videoPktSize;
  int tecm_offset = 0x2a;

  byte_ptr = 0x1a;
  iface = pktBytes((u_char *) rcv_pkt, byte_ptr, 4);        // Capture module interface?
  
  byte_ptr = tecm_offset + 0x10;                            // Protocol?
  ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
  if (ubytes==0x88b5) {                                     // AVTP protocol
    byte_ptr = tecm_offset + 0x26;                          // Pkt size?
    videoPktSize = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);
    byte_ptr = tecm_offset + 0x2a;
    ubytes = pktBytes((u_char *) rcv_pkt, byte_ptr, 2);     // First 2 bytes
    switch(iface) {
      case 6 :                                              // Front camera
        if (ubytes==0xffd8) fIdx=0;                         // Start of video frame
        memcpy(&fFrame[fIdx], &rcv_pkt[byte_ptr], videoPktSize);
        fIdx += videoPktSize;
        ubytes1 = byte_ptr + videoPktSize - 2;              // Last 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, ubytes1, 2);  // Last 2 bytes
        if (ubytes==0xffd9) {                               // End of video frame
          fwrite(fFrame, 1, fIdx, fVideo);                  // Display video frame
          fIdx = 0;
        }
        break;
      case 8:                                               // Driver camera
        if (ubytes==0xffd8) dIdx=0;                         // Start of video frame
        memcpy(&dFrame[dIdx], &rcv_pkt[byte_ptr], videoPktSize);
        dIdx += videoPktSize;
        ubytes1 = byte_ptr + videoPktSize - 2;              // Last 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, ubytes1, 2);  // Last 2 bytes
        if (ubytes==0xffd9) {                               // End of video frame
          fwrite(dFrame, 1, dIdx, dVideo);                  // Display video frame
          dIdx = 0;
        }
        break;
      case 10:                                              // Passenger camera
        if (ubytes==0xffd8) pIdx=0;                         // Start of video frame
        memcpy(&pFrame[pIdx], &rcv_pkt[byte_ptr], videoPktSize);
        pIdx += videoPktSize;
        ubytes1 = byte_ptr + videoPktSize - 2;              // Last 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, ubytes1, 2);  // Last 2 bytes
        if (ubytes==0xffd9) {                               // End of video frame
          fwrite(pFrame, 1, pIdx, pVideo);                  // Display video frame
          pIdx = 0;
        }
        break;
      case 12:                                              // Rear camera
        if (ubytes==0xffd8) rIdx=0;                         // Start of video frame
        memcpy(&rFrame[rIdx], &rcv_pkt[byte_ptr], videoPktSize);
        rIdx += videoPktSize;
        ubytes1 = byte_ptr + videoPktSize - 2;              // Last 2 bytes index
        ubytes = pktBytes((u_char *) rcv_pkt, ubytes1, 2);  // Last 2 bytes
        if (ubytes==0xffd9) {                               // End of video frame
          fwrite(rFrame, 1, rIdx, rVideo);                  // Display video frame
          rIdx = 0;
        }
        break;
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

  /* Set up ffmpeg to capture the four cameras' video frame and display on monitor */
  printf("Capturing all cameras interface ...\n");
  fVideo = popen("ffmpeg -f image2pipe -vcodec mjpeg -i - -an -pix_fmt yuv420p -f sdl2 -loglevel quiet Front", "w");
  dVideo = popen("ffmpeg -f image2pipe -vcodec mjpeg -i - -an -pix_fmt yuv420p -f sdl2 -loglevel quiet Driver", "w");
  pVideo = popen("ffmpeg -f image2pipe -vcodec mjpeg -i - -an -pix_fmt yuv420p -f sdl2 -loglevel quiet Passenger", "w");
  rVideo = popen("ffmpeg -f image2pipe -vcodec mjpeg -i - -an -pix_fmt yuv420p -f sdl2 -loglevel quiet Rear", "w");

  if(bind_core >= 0)
    bind2core(bind_core);
  
  while(1) {
    u_char *buffer;
    struct pfring_pkthdr hdr;
    
    if(pfring_recv(a_ring, &buffer, 0, &hdr, 1) > 0) {
      
      /* Checking for camera AVTP messages and display video frame */
      if(use_pfring_send) {
        cameraPkt((u_char *) buffer, hdr.caplen);
      }	
    }
  }

  pfring_close(a_ring);
  fclose(fVideo);
  fclose(dVideo);
  fclose(pVideo);
  fclose(rVideo);
  
  return(0);
}
