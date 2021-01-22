import glob
import binascii

def start(path):
    
    list1 = path
    #glob.glob(r'C:\Users\Shin\Desktop\Anti-Virus Project\졸작 사진\*')
# 리눅스 절대 경로상의 모든 파일 / *
# 파일마다 바이너리 텍스트 파일로

    for i in range(0, len(list1)):
        filename = list1[i]

        with open(filename, 'rb+') as f:
               content = f.read()

        content = binascii.b2a_hex(content).decode()
        content_size = len(content) * 4
        content = (bin(int(content, 16))[2:]).zfill(content_size)
        fo= open(r"Text\tempBinaries%s.txt" %i,'w')
        fo.write(content)
        fo.close()
