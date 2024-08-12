import argparse
import os
import sys
import subprocess
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from timeit import default_timer as timer

jfif_dir = "./jfif/"

# Select a camera link to extract its AVTP messages from a pcap file. Then consolidate and save the AVTP messages into individual video frame.
def process_pcap_video(file_name):

    frameStart = False
    avtp_frame = []

    # Filter non IPv4/TCP packets
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0
    frame_count = 0

    # Setup for real-time display for video frames on the monitor
    ffmpeg_cmd = [
        "ffmpeg",
        "-f", "image2pipe",
        "-vcodec", "mjpeg",
        "-i", "-",
        "-an",
        "-pix_fmt", "yuv420p",
        "-f", "sdl2",
        "JFIF_Display"
    ]
    ffmpeg_process = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)
    fvideo = ffmpeg_process.stdin

    start = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        inter_id = pkt_data[0x1d]
        if inter_id != 0x06:                        # selected camera link: Fcam-0x06, Dcam-0x08, Pcam-0x0a, Rcam-0x0c
            # disregard other interface
            continue

        tecm_data = pkt_data[0x2a:]                 # strip tecm packet
        ether_pkt = Ether(tecm_data)

        pkt_payload = ether_pkt.payload
        if pkt_payload.type != 0x88b5:
            # disregard non-AVTP packets
            continue

        interesting_packet_count += 1

        avtp_payload = pkt_payload.original[0x1c:-4]
        if avtp_payload[0:2] == b'\xff\xd8':        # start of video frame
            avtp_frame = avtp_payload
            frameStart = True
        else:
            avtp_frame += avtp_payload

        if (frameStart and (avtp_payload[-2:] == b'\xff\xd9')):     # end of video frame
            now = timer()
            while (now-start) < 0.0333:                             # simulate real time display at 30fps
                now = timer()
            start = now
            frame_count += 1
            fvideo.write(avtp_frame)
            jfif_file = "frame" + str(frame_count).zfill(4) +".jfif" # save video frame file
            fname = jfif_dir + jfif_file
            with open(fname, "wb") as binary_file:
                # Write bytes to file
                binary_file.write(avtp_frame)
            frameStart = False

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    # Select a camera link to extract its AVTP messages from a pcap file. Then consolidate and save the AVTP messages into individual video frame.
    process_pcap_video(file_name)
    sys.exit(0)
