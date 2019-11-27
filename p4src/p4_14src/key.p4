#define HEADER_KEY(i) \
    header_type nc_key_##i##_t { \
        fields { \
            key_##i##_1: 32; \
            key_##i##_2: 32; \
            key_##i##_3: 32; \
            key_##i##_4: 32; \
        } \
    } \
    header nc_key_##i##_t nc_key_##i;

#define PARSER_KEY(i, ip1) \
    parser parse_nc_key_##i { \
        extract (nc_key_##i); \
        return parse_nc_key_##ip1; \
    }

#define REGISTER_KEY_SLICE(i, j) \
    register key_##i##_##j##_reg { \
        width: 32; \
        instance_count: NUM_CACHE; \
    }

#define REGISTER_KEY(i) \
    REGISTER_KEY_SLICE(i, 1) \
    REGISTER_KEY_SLICE(i, 2) \
    REGISTER_KEY_SLICE(i, 3) \
    REGISTER_KEY_SLICE(i, 4)

#define ACTION_READ_KEY_SLICE(i, j) \
    action read_key_##i##_##j##_act() { \
        register_read(nc_key_##i.key_##i##_##j, key_##i##_##j##_reg, nc_cache_md.cache_index); \
    }

#define ACTION_READ_KEY(i) \
    ACTION_READ_KEY_SLICE(i, 1) \
    ACTION_READ_KEY_SLICE(i, 2) \
    ACTION_READ_KEY_SLICE(i, 3) \
    ACTION_READ_KEY_SLICE(i, 4)

#define TABLE_READ_KEY_SLICE(i, j) \
    table read_key_##i##_##j { \
        actions { \
            read_key_##i##_##j##_act; \
        } \
    }

#define TABLE_READ_KEY(i) \
    TABLE_READ_KEY_SLICE(i, 1) \
    TABLE_READ_KEY_SLICE(i, 2) \
    TABLE_READ_KEY_SLICE(i, 3) \
    TABLE_READ_KEY_SLICE(i, 4)

#define ACTION_ADD_KEY_HEADER(i) \
    action add_key_header_##i##_act() { \
        add_to_field(ipv4.totalLen, 16);\
        add_to_field(udp.len, 16);\
        add_header(nc_key_##i); \
    }

#define TABLE_ADD_KEY_HEADER(i) \
    table add_key_header_##i { \
        actions { \
            add_key_header_##i##_act; \
        } \
    }

#define ACTION_WRITE_KEY_SLICE(i, j) \
    action write_key_##i##_##j##_act() { \
        register_write(key_##i##_##j##_reg, nc_cache_md.cache_index, nc_key_##i.key_##i##_##j); \
    }

#define ACTION_WRITE_KEY(i) \
    ACTION_WRITE_KEY_SLICE(i, 1) \
    ACTION_WRITE_KEY_SLICE(i, 2) \
    ACTION_WRITE_KEY_SLICE(i, 3) \
    ACTION_WRITE_KEY_SLICE(i, 4)

#define TABLE_WRITE_KEY_SLICE(i, j) \
    table write_key_##i##_##j { \
        actions { \
            write_key_##i##_##j##_act; \
        } \
    }

#define TABLE_WRITE_KEY(i) \
    TABLE_WRITE_KEY_SLICE(i, 1) \
    TABLE_WRITE_KEY_SLICE(i, 2) \
    TABLE_WRITE_KEY_SLICE(i, 3) \
    TABLE_WRITE_KEY_SLICE(i, 4)

#define ACTION_REMOVE_KEY_HEADER(i) \
    action remove_key_header_##i##_act() { \
        subtract_from_field(ipv4.totalLen, 16);\
        subtract_from_field(udp.len, 16);\
        remove_header(nc_key_##i); \
    }

#define TABLE_REMOVE_KEY_HEADER(i) \
    table remove_key_header_##i { \
        actions { \
            remove_key_header_##i##_act; \
        } \
    }

#define ACTION_CHECK_COLLISION(i) \
    action check_collision_##i##_act() { \
        extract(nc_load)
        if(nc_load.load_1 != (nc_key_##i.key_##i##_1) {
            modify_field (nc_cache_md.cache_valid, 0);
        }
        else if(nc_load.load_2 != (nc_key_##i.key_##i##_2) {
            modify_field (nc_cache_md.cache_valid, 0);
        }
        else if(nc_load.load_3 != (nc_key_##i.key_##i##_3) {
            modify_field (nc_cache_md.cache_valid, 0);
        }
        else if(nc_load.load_4 != (nc_key_##i.key_##i##_4) {
            modify_field (nc_cache_md.cache_valid, 0);
        }
    }

#define TABLE_CHECK_COLLISION(i) \
    table check_collision_##i { \
        actions { \
            check_collision_##i##_act; \
        } \
    }

#define CONTROL_PROCESS_KEY(i) \
    control process_key_##i { \
        if (nc_hdr.op == NC_READ_REQUEST and nc_cache_md.cache_valid == 1) { \
            apply (add_key_header_##i); \
            apply (read_key_##i##_1); \
            apply (read_key_##i##_2); \
            apply (read_key_##i##_3); \
            apply (read_key_##i##_4); \
            apply (check_collision_##i); \
            apply (remove_key_header_##i); \
        } \
        else if (nc_hdr.op == NC_UPDATE_KEY_REPLY and nc_cache_md.cache_exist == 1) { \
            apply (write_key_##i##_1); \
            apply (write_key_##i##_2); \
            apply (write_key_##i##_3); \
            apply (write_key_##i##_4); \
            apply (remove_key_header_##i); \
        } \
    }

#define HANDLE_KEY(i, ip1) \
    HEADER_KEY(i) \
    PARSER_KEY(i, ip1) \
    REGISTER_KEY(i) \
    ACTION_READ_KEY(i) \
    TABLE_READ_KEY(i) \
    ACTION_ADD_KEY_HEADER(i) \
    TABLE_ADD_KEY_HEADER(i) \
    ACTION_WRITE_KEY(i) \
    TABLE_WRITE_KEY(i) \
    ACTION_REMOVE_KEY_HEADER(i) \
    TABLE_REMOVE_KEY_HEADER(i) \
    CONTROL_PROCESS_KEY(i)

#define FINAL_PARSER(i) \
    parser parse_nc_key_##i { \
        return ingress; \
    }

HANDLE_KEY(1, 2)
HANDLE_KEY(2, 3)
HANDLE_KEY(3, 4)
HANDLE_KEY(4, 5)
HANDLE_KEY(5, 6)
HANDLE_KEY(6, 7)
HANDLE_KEY(7, 8)
HANDLE_KEY(8, 9)
FINAL_PARSER(9)

control process_key {
    process_key_1();
    process_key_2();
    process_key_3();
    process_key_4();
    process_key_5();
    process_key_6();
    process_key_7();
    process_key_8();
}
