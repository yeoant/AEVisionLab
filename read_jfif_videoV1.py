import sys
import glob
import subprocess
from natsort import natsorted
from timeit import default_timer as timer

if __name__ == '__main__':

    # input
    input_jfif_dir = sys.argv[1]
    print(input_jfif_dir)

    # consolidate jfif file names from folder
    mylist = [f for f in glob.glob(input_jfif_dir+"*.jfif")]

    # sorting the list in ascending order
    mylist=natsorted(mylist)

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
    for f in mylist:
        with open(f, "rb") as input_binary_file:    # read video frame from jfif file
            # read bytes to file
            avtp_frame = input_binary_file.read()
        now = timer()
        while (now-start) < 0.0333:                 # simulate real time display at 30fps
            now = timer()
        start = now
        fvideo.write(avtp_frame)

