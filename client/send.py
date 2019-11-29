import socket
import struct
import time
import thread

from nc_config import *

NC_PORT = 8888
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CONTROLLER_IP = "10.0.0.3"
path_query = "query.txt"
query_rate = 1000

len_key = 16

counter = 0
def counting():
    last_counter = 0
    while True:
        print (counter - last_counter), counter
        last_counter = counter
        time.sleep(1)
thread.start_new_thread(counting, ())

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
f = open(path_query, "r")
interval = 1.0 / (query_rate + 1)
lines = f.readlines();
skip = False
for l in range(len(lines)):
    if(skip):
        skip = False
        continue
    line = lines[l].split()
    op = line[0]
    key_header = int(line[1])
    key_body = line[2:]

    if op == 'get':
        op_field = struct.pack("B", NC_READ_REQUEST)
    if op == 'put':
        op_field = struct.pack("B", NC_WRITE_REQUEST)
    key_field = ""
    if len_key < 4 + len(key_body):
        print("Keys too long, please regen")
        sys.exit()
    key_field += struct.pack(">I", key_header)
    pad = len_key - (4 + len(key_body))
    for i in range(pad):
        key_field += struct.pack("B", 0)
    for i in range(len(key_body)):
        key_field += struct.pack("B", int(key_body[i], 16))
    packet = op_field + key_field
    if op == 'put':
        line = lines[l+1].split()
        val_field = ""
        for i in range(len(line)):
            val_field += struct.pack("B", int(line[i], 16))
        packet += val_field
        skip = True
    s.sendto(packet, (SERVER_IP, NC_PORT))
    counter = counter + 1
    time.sleep(interval)

f.close()
