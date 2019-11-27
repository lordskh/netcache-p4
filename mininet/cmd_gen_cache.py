import struct
import binascii

path_to_cmd = "commands_cache.txt"
path_hot = "hot.txt"
max_hot = 100

len_key = 16

fcmd = open(path_to_cmd, "w")
f = open(path_hot, "r")
for line in f.readlines():
    line = line.split()
    key_header = line[0]
    key_body = line[1:]

    key_header = int(key_header)
    for i in range(len(key_body)):
        key_body[i] = int(key_body[i], 16)

    key_field = ""
    key_field += struct.pack(">I", key_header)
    for i in range(len(key_body)):
        key_field += struct.pack("B", key_body[i])

    key_hash = binascii.crc32(key_field) % (1<<32)
    fcmd.write("table_add check_cache_exist check_cache_exist_act %d => %d\n" % (key_hash, key_header))
f.close()
fcmd.flush()
fcmd.close()
