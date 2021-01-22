import sys
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import webbrowser
import subprocess

from tensorflow.compat.v1 import ConfigProto
from tensorflow.compat.v1 import InteractiveSession
from PIL import Image

config = ConfigProto()
config.gpu_options.allow_growth = True
session = InteractiveSession(config=config)

from matplotlib import pyplot as plt

import numpy as np
import tensorflow as tf

from nets import inception
from preprocessing import inception_preprocessing

from os.path import getsize
import shutil
import time
import glob
import binascii

#####qt deginer 사용#####
from PyQt5.QtWidgets import *
from PyQt5 import uic
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QTimer
#####MD5값 불러오기######
from string import ascii_lowercase
import hashlib
#####DB정보 불러오기#####
import pymysql

import Classification_malwares
import ToGrayScale
import ToBinary


f = open('test.txt', 'r')    # DB에서 가져온 값이 저장돼 있는 메모장
lines = f.readlines()
f.close()

form_class1 = uic.loadUiType("main.ui")[0] # 메인윈도우
form_class2 = uic.loadUiType("fast.ui")[0] # 빠른검사
form_class3 = uic.loadUiType("slow.ui")[0] # 정밀검사
form_class4 = uic.loadUiType("update.ui")[0] # 업데이트
form_class5 = uic.loadUiType("file_path.ui")[0] # 탐지파일 경로

set_text_1 = "업데이트를 하시려면 오른쪽의 버튼을 눌러주세요" #메인화면 아래쪽에 뜨는 문구
set_text_2 = "정밀검사 기능은 상당히 느립니다"   #메인화면 아래쪽에 뜨는 문구

path2 = list()  # 탐지파일 경로에 써먹음
find = list()   # 요것도
hash_list=list() #일치 할 경우 해시 값 저장

path_select = 0 # 파일검사, 폴더검사 구별할때 씀

#########################빠른검사창#########################
class Fast_check(QDialog, form_class2):
    def __init__(self, parent=None):
        super(Fast_check, self).__init__(parent)
        self.setupUi(self)
        self.setFixedSize(913, 513)#사이즈 고정
        self.find_path.clicked.connect(self.select_file)#파일검색
        self.find_path2.clicked.connect(self.select_folder)#폴더검색
        self.finish_button2.setDisabled(True) #버튼 비활성화
        self.check.clicked.connect(self.check_hash)#검사
        self.finish_button.clicked.connect(self.finish)
        self.finish_button2.clicked.connect(self.Find_file_path)
        self.loading.reset()
        self.check.setDisabled(True)
        
        
    # 파일 경로 선택
    def select_file(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', "", "All Files(*)")
        aname = list(fname)
        self.path.setText(aname[0])
        global path_select
        path_select = 1
        self.check.setDisabled(False)

    # 폴더 경로 선택
    def select_folder(self):
        fname = QFileDialog.getExistingDirectory(self, "select Directory")
        self.path.setText(fname)
        global path_select
        path_select = 2
        self.check.setDisabled(False)        
        
    # 검사 눌렀을 때 파일경로, 진행상황
    def check_hash(self):
        global hash_list
        self.loading.reset()
        global path2
        for k in range(0, len(path2)):
            try:
                del path2[0]
            except:
                break
        fp = list()
        hasher = list()
        if path_select == 2:
            def search(dirname):    # 지정한 위치 경로 탐색하는 것
                try:
                    filenames = os.listdir(dirname)
                    for filename in filenames:
                        full_filename = os.path.join(dirname, filename)
                        if os.path.isdir(full_filename):
                            search(full_filename)
                        else:
                            if 'c:/$Recycle.Bin' in full_filename:
                                pass
                            else:
                                afile = open(full_filename, 'rb')
                                data = afile.read()
                                hash1 = hashlib.md5(data).hexdigest()
                                fp.append(full_filename)
                                hasher.append(r"('" + hash1 + "\n")
                except PermissionError:
                    pass
            search(self.path.text())
        self.loading.setValue(10)
        self.loading.setValue(20)
        self.loading.setValue(30)
        path_find = 0
        path_pass = 0
        path = 0

        if path_select == 1:
            afile = open(self.path.text(), 'rb')
            data = afile.read()
            hash1 = hashlib.md5(data).hexdigest()
            hasher.append(r"('" + hash1 + "\n")
            temp = self.path.text().split('/')
            fp.append("\\".join(temp))
        
        for i in hasher:
            QApplication.processEvents()
            if i in lines: # 메모장 해시값 = 내 컴터 해시값
                hash_list.append(i)
                path_find = path_find + 1
                self.path_find.setText(str(path_find))
                self.path_find.repaint()
                if path_select == 1:
                    self.file_path.append(self.path.text())
                    find.append(fp[0])
                    break
                self.file_path.append(fp[path])
                find.append(fp[path])
                path = path + 1
                if i == hasher[int(len(hasher)/8)]:
                    self.loading.setValue(40)
                elif i == hasher[int(len(hasher)/3)]:
                    self.loading.setValue(50)
                elif i == hasher[int(len(hasher)/2)]:
                    self.loading.setValue(60)
                elif i == hasher[int(len(hasher)*2/3)]:
                    self.loading.setValue(70)
                elif i == hasher[int(len(hasher)*4/5)]:
                    self.loading.setValue(80)
                elif i == hasher[int(len(hasher)*9/10)]:
                    self.loading.setValue(90)
            else:               # 메모장 해시값 ≠ 내 컴터 해시값
                path_pass = path_pass + 1
                self.path_pass.setText(str(path_pass))
                self.path_pass.repaint()
                if path_select == 1:
                    self.file_path.append(self.path.text())
                    break
                self.file_path.append(fp[path])
                path = path + 1
                if i == hasher[int(len(hasher)/8)]:
                    self.loading.setValue(40)
                elif i == hasher[int(len(hasher)/3)]:
                    self.loading.setValue(50)
                elif i == hasher[int(len(hasher)/2)]:
                    self.loading.setValue(60)
                elif i == hasher[int(len(hasher)*2/3)]:
                    self.loading.setValue(70)
                elif i == hasher[int(len(hasher)*4/5)]:
                    self.loading.setValue(80)
                elif i == hasher[int(len(hasher)*9/10)]:
                    self.loading.setValue(90)
        self.finish_button2.setDisabled(False) # 버튼 활성화
        
        for j in range(0,len(hash_list)):   #hash_list안에 든 해시 값 인덱싱해서 불필요한 부분 자르기
            hash_list[j]=(hash_list[j])[2:-1]
        for i in find:
            path2.append(i)
        self.loading.setValue(100)

    # 메모장 해시값 = 내 컴터 해시값일 때 여는 경로창
    def Find_file_path(self):
        self.newWindow = File_path(self)
        self.newWindow.show()

    # 종료버튼
    def finish(self):
        self.close()

# 파일 경로 걸리면 뜨는 창
class File_path(QDialog, form_class5):
        def __init__(self, parent=None):
            super(File_path, self).__init__(parent)
            self.setupUi(self)
            self.setFixedSize(630, 360)
            self.file_path.clicked.connect(self.f_path)
            self.file_info.clicked.connect(self.f_info)
            self.file_delete.clicked.connect(self.f_delete)

            hash_list = []  #일치 할 경우 해시 값 저장

            self.find_file_path.clear()
            self.find_file_path.update()
            #print(path2)
            for i in path2: #화면 리스트에 해당 파일 경로 추가
                self.find_file_path.addItem(i)


        def f_path(self):   #파일 위치 열어주기
            b = self.find_file_path.currentItem().text()  #해당파일의 경로 읽어오기
            a = b.split('\\') #\기준으로 나눠서 배열에 저장하기
            a.pop() #마지막 배열에 들어간 값은 파일이름이므로 제외
            path="\\".join(a)   #나머지 경로 합치기
            path = os.path.realpath(path)
            os.startfile(path)
            print(path)

        def f_info(self):
            item_num = self.find_file_path.currentRow() #경로창에서 몇번째 악성코드의 경로를 눌렀는지 반환하는값
            click_path_hash = hash_list[item_num]   #해당 경로에 악성코드의 해시값
            url = 'https://www.virustotal.com/gui/file/'+click_path_hash+'/detection'   #해당 해시 값 바이러스 토탈의 검색한 결과 창
            webbrowser.open_new_tab(url)    #URL 오픈

        def f_delete(self):
            path = self.find_file_path.currentItem().text()  #누른 아이템의 경로 읽어오기

            for i in range(0,len(self.find_file_path)):
                try:
                    if path == self.find_file_path.item(i).text():
                        self.find_file_path.takeItem(i)
                except:
                    continue
            os.remove(path)

#########################정밀검사창#########################
class Slow_check(QDialog, form_class3):
    def __init__(self, parent=None):
        super(Slow_check, self).__init__(parent)
        self.setupUi(self)
        self.setFixedSize(913, 513)#사이즈 고정
        self.find_path.clicked.connect(self.select_file)#파일검색
        self.find_path2.clicked.connect(self.select_folder)#폴더검색
        self.finish_button2.setDisabled(True) #버튼 비활성화
        self.check.clicked.connect(self.check_hash)#검사
        self.finish_button.clicked.connect(self.finish)
        self.finish_button2.clicked.connect(self.Find_file_path)
        self.loading.reset()

    # 파일 경로 선택
    def select_file(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', "", "All Files(*)")
        aname = list(fname)
        self.path.setText(aname[0])
        global path_select
        path_select = 1
        self.check.setDisabled(False)

    # 폴더 경로 선택
    def select_folder(self):
        fname = QFileDialog.getExistingDirectory(self, "select Directory")
        self.path.setText(fname)
        global path_select
        path_select = 2
        self.check.setDisabled(False)

    # 여기에 함수 넣으면댐
    def check_hash(self):
        try:
            shutil.rmtree("Text")
        except:
            pass
        os.mkdir("Text")
        os.mkdir("Text\GrayScale")
        
        global path2
        for k in range(0, len(path2)):
            try:
                del path2[0]
            except:
                break
        self.loading.reset()
        fp = list()
        hasher = list()
        if path_select == 2:
            def search(dirname):    # 지정한 위치 경로 탐색하는 것
                try:
                    filenames = os.listdir(dirname)
                    for filename in filenames:
                        full_filename = os.path.join(dirname, filename)
                        if os.path.isdir(full_filename):
                            search(full_filename)
                        else:
                            if 'c:/$Recycle.Bin' in full_filename:
                                pass
                            else:
                                afile = open(full_filename, 'rb')
                                data = afile.read()
                                hash1 = hashlib.md5(data).hexdigest()
                                fp.append(full_filename)
                                hasher.append(r"('" + hash1 + "\n")
                except PermissionError:
                    pass
            search(self.path.text())
        self.loading.setValue(10)
        path_find = 0
        path_pass = 0
        path = 0
        j = 0
        
        if path_select == 1:
            afile = open(self.path.text(), 'rb')
            data = afile.read()
            hash1 = hashlib.md5(data).hexdigest()
            hasher.append(r"('" + hash1 + "\n")
            temp = self.path.text().split('/')
            fp.append("\\".join(temp))
        self.loading.setValue(20)
        ToBinary.start(fp)
        ToGrayScale.start()
        self.loading.setValue(30)
        for i in hasher:
            QApplication.processEvents()
            if i in lines: # 메모장 해시값 = 내 컴터 해시값
                hash_list.append(i)
                path_find = path_find + 1
                self.path_find.setText(str(path_find))
                self.path_find.repaint()
                if path_select == 1:
                    self.file_path.append(self.path.text())
                    find.append(fp[0])
                    break
                self.file_path.append(fp[path])
                find.append(fp[path])
                path = path + 1
                if i == hasher[int(len(hasher)/8)]:
                    self.loading.setValue(40)
                elif i == hasher[int(len(hasher)/3)]:
                    self.loading.setValue(50)
                elif i == hasher[int(len(hasher)/2)]:
                    self.loading.setValue(60)
                elif i == hasher[int(len(hasher)*2/3)]:
                    self.loading.setValue(70)
                elif i == hasher[int(len(hasher)*4/5)]:
                    self.loading.setValue(80)
                elif i == hasher[int(len(hasher)*9/10)]:
                    self.loading.setValue(90)
            else:               # 메모장 해시값 ≠ 내 컴터 해시값
                detecting = Classification_malwares.Cnn_Check(j)
                if detecting == "Detected":
                    hash_list.append(i)
                    path_find = path_find + 1
                    self.path_find.setText(str(path_find))
                    self.path_find.repaint()
                    if path_select == 1:
                        self.file_path.append(self.path.text())
                        find.append(fp[0])
                        break
                    self.file_path.append(fp[path])
                    find.append(fp[path])
                    path = path + 1
                else:
                    path_pass = path_pass + 1
                    self.path_pass.setText(str(path_pass))
                    self.path_pass.repaint()
                    if path_select == 1:
                        self.file_path.append(self.path.text())
                        break
                    self.file_path.append(fp[path])
                    path = path + 1
                if i == hasher[int(len(hasher)/8)]:
                    self.loading.setValue(40)
                elif i == hasher[int(len(hasher)/3)]:
                    self.loading.setValue(50)
                elif i == hasher[int(len(hasher)/2)]:
                    self.loading.setValue(60)
                elif i == hasher[int(len(hasher)*2/3)]:
                    self.loading.setValue(70)
                elif i == hasher[int(len(hasher)*4/5)]:
                    self.loading.setValue(80)
                elif i == hasher[int(len(hasher)*9/10)]:
                    self.loading.setValue(90)
            j += 1

        self.finish_button2.setDisabled(False) # 버튼 활성화
        
        for j in range(0,len(hash_list)):   #hash_list안에 든 해시 값 인덱싱해서 불필요한 부분 자르기
            hash_list[j]=(hash_list[j])[2:-1]
        for i in find:
            path2.append(i)
        self.loading.setValue(100)

    # 메모장 해시값 = 내 컴터 해시값일 때 여는 경로창
    def Find_file_path(self):
        self.newWindow = File_path(self)
        self.newWindow.show()

    # 종료버튼
    def finish(self):
        self.close()

# 파일 경로 걸리면 뜨는 창
class File_path(QDialog, form_class5):
        def __init__(self, parent=None):
            super(File_path, self).__init__(parent)
            self.setupUi(self)
            self.setFixedSize(630, 360)
            self.file_path.clicked.connect(self.f_path)
            self.file_info.clicked.connect(self.f_info)
            self.file_delete.clicked.connect(self.f_delete)

            hash_list = []  #일치 할 경우 해시 값 저장
            
            for i in path2: #화면 리스트에 해당 파일 경로 추가
                self.find_file_path.addItem(i)

        def f_path(self):   #파일 위치 열어주기
            b = self.find_file_path.currentItem().text()  #해당파일의 경로 읽어오기
            a = b.split('\\') #\기준으로 나눠서 배열에 저장하기
            a.pop() #마지막 배열에 들어간 값은 파일이름이므로 제외
            path="\\".join(a)   #나머지 경로 합치기
            path = os.path.realpath(path)
            os.startfile(path)

        def f_info(self):
            item_num = self.find_file_path.currentRow() #경로창에서 몇번째 악성코드의 경로를 눌렀는지 반환하는값
            click_path_hash = hash_list[item_num]   #해당 경로에 악성코드의 해시값
            url = 'https://www.virustotal.com/gui/file/'+click_path_hash+'/detection'   #해당 해시 값 바이러스 토탈의 검색한 결과 창
            webbrowser.open_new_tab(url)    #URL 오픈

        def f_delete(self):
            path = self.find_file_path.currentItem().text()  #누른 아이템의 경로 읽어오기

            for i in range(0,len(self.find_file_path)):
                try:
                    if path == self.find_file_path.item(i).text():
                        self.find_file_path.takeItem(i)
                except:
                    continue
            os.remove(path)
#######################업데이트 팝업창#####################
class Version_update(QDialog, form_class4):
    def __init__(self, parent=None):
        super(Version_update, self).__init__(parent)
        self.setFixedSize(400, 300)
        self.setupUi(self)

        self.pushButton.clicked.connect(self.start_update)
        self.pushButton2.clicked.connect(self.close_window)

    # 창 종료
    def close_window(self):
        self.close()


    # DB에서 해시값 불러와서 메모장에 저장 한 후, 저장된 해시값에서 \r',) <- 요거 삭제해서 다른 메모장에 저장 (DB에서 불러오면 튜플값이어서 변경 후 저장이 안댐)
    # 사실 해시값 맨앞에 ( <- 요것도 있는데 없애는법 모르겠어서 
    def start_update(self):
        self.pushButton.setDisabled(True) # 버튼 비활성화
        self.pushButton2.setDisabled(True) # 버튼 비활성화
        self.label.setText("      업데이트 중")
        self.label.repaint()
        connection = pymysql.connect(host='34.64.253.74', port=3306, user='onlyread', passwd='', db='malware_hash', charset='utf8')

        cur = connection.cursor()

        query = "select * from MD5" 
        cur.execute(query)
        datas = cur.fetchall()

        c = [data for data in datas]

        connection.commit()
        connection.close()

        f = open(r'save.txt', 'w')
        for i in c:
            f.writelines(str(i) + '\n')
        f.close()

        file = open(r"save.txt",'r')
        lines = file.read().splitlines()
        file.close()

        saved = open(r"DB_hash.txt", "w")
        for line in lines:
            saved.write(line.split(r"\r',)")[0]+"\n")
        saved.close()

        self.label.setText("      업데이트 완료")
        self.label.repaint()

        self.pushButton.setDisabled(False) # 버튼 비활성화
        self.pushButton2.setDisabled(False) # 버튼 비활성화

##########################메인화면##########################
class WindowClass(QMainWindow, form_class1):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setFixedSize(1120, 675)
        self.button1.clicked.connect(self.button_clicked1)
        self.button2.clicked.connect(self.button_clicked2)
        self.update.clicked.connect(self.update_button)
        self.timer = QTimer(self)
        self.timer.start(5000)
        self.timer.timeout.connect(self.timeout_run)
        self.textEdit.setText(set_text_1)
        
    def timeout_run(self):
        if self.textEdit.toPlainText() == set_text_1:
            self.textEdit.setText(set_text_2)    
        else:
            self.textEdit.setText(set_text_1)
        
    # 빠른 검사창 생성
    def button_clicked1(self):
        self.newWindow = Fast_check(self)
        self.newWindow.show()

    # 정밀 검사창 생성
    def button_clicked2(self):
        self.newWindow = Slow_check(self)
        self.newWindow.show()

    # 업데이트 창 생성
    def update_button(self):
        self.newWindow = Version_update(self)
        self.newWindow.show()



app = QApplication(sys.argv)
mywindow = WindowClass()
mywindow.show()
app.exec_()
