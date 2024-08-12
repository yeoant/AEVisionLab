import sys
import cv2
import numpy as np
import os


def modify_pixel(img, x, y, new_value):
    img[y, x] = new_value    


if __name__ == '__main__':

    # input jfif file
    input_jfif_file = sys.argv[1]

    # Convert jfif 12 bit image to raw pnm
    os.system(f'"/home/master/Automotive Ethernet Test Platform/AE Scripts/Python Code/djpeg" "{input_jfif_file}" > output_raw.pnm')

    raw_image = cv2.imread('output_raw.pnm', cv2.IMREAD_UNCHANGED | cv2.IMREAD_ANYDEPTH)
    print("Press any key to exit")
    if raw_image is not None:

        # Fix raw image color range (12 bit to 16 bit)
        image = np.uint16(raw_image * 16) # Shift each color value by 4 bits (multiply by 16).
      
        # Show image
        cv2.imshow('image', image)

        # Wait user to press any key
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    
    else:
        print('Error in loading image')
