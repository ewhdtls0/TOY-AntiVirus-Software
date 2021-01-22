import numpy as np
from PIL import Image
from os.path import getsize
import glob

def start():
    def width_limit(path):
        if file_size < 10240:
            width = 32
        elif file_size >= 10240 and file_size < 30720:
            width = 64
        elif file_size >= 30720 and file_size < 61440:
            width = 128
        elif file_size >= 61440 and file_size < 102400:
            width = 256
        elif file_size >= 102400 and file_size < 204800:
            width = 384
        elif file_size >= 204800 and file_size < 512000:
            width = 512
        elif file_size >= 512000 and file_size < 1024000:
            width = 768
        elif file_size >= 1024000:
            width = 1024
        return width

    All_files = glob.glob(r"Text\*.txt")

    for files in range(0, len(All_files)):
        try:
            path = All_files[files]
            file = open(path, 'r')
            file_size = getsize(path)

            width = width_limit(path)
            count = 0
            binary = list(file.readline())
            height = int(len(binary) / width)
            vector = [[0] * width for i in range(height)]
            list1 = []
            row = 0
            for i in binary:
                list1.append(i)
                count += 1
                if count % width is 0:
                    vector[row] = list1
                    list1 = []
                    row += 1

            vector = np.array(vector, dtype="uint8")

            im = Image.fromarray(vector * 255)
            im.save(r"Text\GrayScale\input%s.jpg" % files)
        # 파일마다 흑백 jpg 파일로
        except:
            continue

    print("Conversion complete")
