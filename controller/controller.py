import socket
import struct
import time
import thread
from nc_config import *

NC_PORT = 8888
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CONTROLLER_IP = "10.0.0.3"
path_hot = "hot.txt"
path_log = "controller_log.txt"

len_key = 16
len_val = 128

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((CONTROLLER_IP, NC_PORT))

## Initiate the switch
op = NC_UPDATE_REQUEST
op_field = struct.pack("B", op)
f = open(path_hot, "r")
for line in f.readlines():
    line = line.split()
    key_header = line[0]
    key_body = line[1:]

    key_header = int(key_header)
    for i in range(len(key_body)):
        key_body[i] = int(key_body[i], 16)

    key_field = ""
    if len_key < 4 + len(key_body):
        print("Keys too long, please regen")
        sys.exit()
    key_field += struct.pack(">I", key_header)
    pad = len_key - (4 + len(key_body))
    for i in range(pad):
        key_field += struct.pack("B", 0)
    for i in range(len(key_body)):
        key_field += struct.pack("B", key_body[i])

    packet = op_field + key_field
    s.sendto(packet, (SERVER_IP, NC_PORT))
    time.sleep(0.001)
f.close()

cachekeys = []
hhkeys = []
hits = {}
hhhits = {}

def clear_hh():
    global cachekeys
    global hhkeys
    global hits
    global hhhits
    while True:
        time.sleep(10)
        for k in hhkeys:
            try:
                hits[k] += hhhits[k]
            except KeyError:
                hits[k] = hhhits[k]
            hhhits[k] = 0
        op = NC_CLEAR_HOT
        op_field = struct.pack("B", op)
        key_field = ""
        for i in range(len_key):
            key_field += struct.pack("B", 0)
        packet = op_field + key_field
        s.sendto(packet, (SERVER_IP, NC_PORT))
thread.start_new_thread(clear_hh, ())

def refresh_cache():
    global cachekeys
    global hhkeys
    global hits
    global hhhits
    while True:
        time.sleep(11)
        for k in cachekeys:
            op = NC_HITS_REQUEST
            op_field = struct.pack("B", op)
            packet = op_field + k
            s.sendto(packet, (SERVER_IP, NC_PORT))
        while(len(hits) > len(cachekeys) + len(hhkeys)):
            continue

        newkeys = sorted(hits, key=hits.get, reverse=True)[:128]
        keepkeys = set(newkeys).intersection(set(cachekeys))
        removekeys = list(set(cachekeys).difference(keepkeys))
        addkeys = list(set(newkeys).difference(keepkeys))

        for k in removekeys:
            op = NC_REMOVE
            op_field = struct.pack("B", op)
            packet = op_field + k
            s.sendto(packet, (SERVER_IP, NC_PORT))
        for k in addkeys:
            op = NC_UPDATE_REQUEST
            op_field = struct.pack("B", op)
            packet = op_field + k
            s.sendto(packet, (SERVER_IP, NC_PORT))

        cachekeys = newkeys
        hhkeys = []
        hits = {}
        hhhits = {}

thread.start_new_thread(refresh_cache, ())
## Listen hot report
#f = open(path_log, "w")
while True:
    packet, addr = s.recvfrom(2048)
    op_field = packet[0]
    key_field = packet[1:len_key + 1]
    load_field = packet[len_key + 1:]

    op = struct.unpack("B", op_field)[0]
    if (op != NC_HOT_READ_REQUEST):
        continue

    key_header = struct.unpack(">I", key_field[:4])[0]
    load = struct.unpack(">IIII", load_field)
    avg_load = sum(load)/len(load)

    if key_field in cachekeys:
        hits[key_field] = avg_load
    else:
        print "\tHot Item:", key_header, load
        hhhits[key_field] =  avg_load
        if key_field not in hhkeys:
            hhkeys.append(key_field)

    #f.write(str(key_header) + ' ')
    #f.write(str(load) + ' ')
    #f.write("\n")
    #f.flush()
#f.close()
