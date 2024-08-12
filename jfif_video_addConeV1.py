import os
import sys
import glob
import subprocess
from natsort import natsorted
from timeit import default_timer as timer
import cv2
import numpy as np

# input jfif files folder
input_jfif_dir = "/media/master/NTFS Disk/road pcap/road_231204_4/jfif/"

# Parameters for adding cone to selected road segment
# select road segment
edit_startNum = 850         # start of road segment: segment1=1, segment2=850
edit_stopNum = 1000         # end of road segment: segment1=250, segment2=1000
# select start and end cone dimension
start_dim = 20              # segment1=5, segment2=20
stop_dim = 100              # segment1=100, segment2=100
s_change = (stop_dim - start_dim) / (edit_stopNum - edit_startNum) # process size changes per frame
# select cone start position - vertical=xstart, horizontal=ystart
xstart = 670                # segment1=660, segment2=670
ystart = 570                # segment1=625, segment2=570
# select relative position change per frame - vertical=x_change, horizontal=y_change
x_change = 1.05             # segment1=0.6, segment2=1.05
y_change = 0                # segment1=-1.0, segment2=0

print('jfif = ', input_jfif_dir, 'start = ', edit_startNum, 'stop = ', edit_stopNum)

# setup RAM memory folder to store processed temporary files for faster processing
ramdisk = "/mnt/ramdisk/"
edit_dir = ramdisk+"edit/"
os.system(f'mkdir -p {ramdisk}')
os.system(f'sudo mount -t tmpfs -o rw,size=4G tmpfs {edit_dir}')
os.system(f'mkdir -p {edit_dir}')
os.system(f'cd {edit_dir} && rm -f *')
output_raw = ramdisk + "output_raw.pnm"
out_txt = ramdisk + "out.txt"

def frame_edit(file_name, fcnt):

    fname = os.path.basename(file_name)
    input_jfif_file = file_name
    output_jfif_file = edit_dir + fname

    # Decompress 12-bit jfif file to raw pnm file
    os.system(f'./djpeg -v -v "{input_jfif_file}" 1> "{output_raw}" 2> "{out_txt}"')

    # Extract Quantization Tables from out.txt to tables.txt
    with open(out_txt, "r") as in_tables:
        # read bytes to file
        q_tab = in_tables.readlines()
    tables_txt = "/mnt/ramdisk/tables.txt"
    with open(tables_txt, "w") as out_tables:
        out_tables.writelines(q_tab[20:28])
        out_tables.writelines('\n')
        out_tables.writelines(q_tab[29:37])
        out_tables.writelines('\n')       

    # Read 12-bit raw pnm file and cone image file
    raw_image = cv2.imread(output_raw, cv2.IMREAD_UNCHANGED | cv2.IMREAD_ANYDEPTH)
    cone_img = cv2.imread("traffic-cone-4.png", -1)

    # Add cone of relative position and size to the image
    if raw_image is not None:

        # Fix raw image color range (12 bit to 16 bit)
        image = np.uint16(raw_image * 16) # Shift each color value by 4 bits (multiply by 16).

        # ------------------ Modify image here ------------------
        # Add cone to the image - Note: Opencv color format is BGR (inverse of RGB)
        x_place = round(xstart + x_change*fcnt)             # process relative cone position in the image
        y_place = round(ystart + y_change*fcnt)
        pix_size = round(start_dim + s_change*fcnt)
        dim = (pix_size, pix_size)
        cone_img = cv2.resize(cone_img, dim)                # resize cone to relative size
        print(fcnt,x_place,y_place,'cone',cone_img.shape,'image',image.shape)

        y1, y2 = y_place, y_place + cone_img.shape[0]
        x1, x2 = x_place, x_place + cone_img.shape[1]
        alpha_cone = cone_img[:, :, 3] / 255.0
        alpha_image = 1.0 - alpha_cone
        for c in range(0, 3):                               # add cone to the image
            image[x1:x2, y1:y2, c] = (alpha_cone * np.uint16(cone_img[:, :, c] * 256) + alpha_image * image[x1:x2, y1:y2, c])

        # -------------------------------------------------------

        # Save raw edited pnm image
        output_raw_edited = "/mnt/ramdisk/output_raw_edited.pnm"
        cv2.imwrite(output_raw_edited, image)

        # Compress 12-bit pnm file to jfif file and preserving its qunatization tables
        os.system(f'./cjpeg -precision 12 -restart 1 \
                  -qtables "{tables_txt}" "{output_raw_edited}" > "{output_jfif_file}"')

        # read back edited jfif file for display purpose
        with open(output_jfif_file, "rb") as edit_binary_file:
            # read bytes to file
            avtp_edit = edit_binary_file.read()
   
    else:
        print('Error in loading image')

    return avtp_edit


if __name__ == '__main__':

    # Initialize
    start = 0
    frame_count = 1
   
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

    for f in mylist:
        with open(f, "rb") as input_binary_file:
            # read bytes to file
            avtp_frame = input_binary_file.read()
        now = timer()
        while (now-start) < 0.0333:             # simulate real time display at 30fps
            now = timer()
        start = now
        if (frame_count >= edit_startNum) & (frame_count <= edit_stopNum):
            fcount = frame_count-edit_startNum + 1
            avtp_frame=frame_edit(f,fcount)     # add cone to road segment
        frame_count += 1
        fvideo.write(avtp_frame)                # display video stream with added cone
