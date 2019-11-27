header_type nc_cache_md_t {
    fields {
        cache_exist: 1;
        cache_index: 14;
        cache_valid: 1;
    }
}
metadata nc_cache_md_t nc_cache_md;

header_type nc_hash_key_t {
    fields {
        hash_key: 4;
    }
}
metadata nc_hash_key_t nc_hash_key;

field_list hk_hash_fields {
    current(0, nc_hdr);
}
field_list_calculation key_hash {
    input {
        hk_hash_fields;
    }
    algorithm : crc32;
    output_width : 32;
}

action get_hash_key_act {
    modify_field (nc_hash_key.hash_key, key_hash);
}
table get_hash_key {
    actions {
        get_hash_key_act;
    }
}

action check_cache_exist_act(index) {
    modify_field (nc_cache_md.cache_exist, 1);
    modify_field (nc_cache_md.cache_index, index);
}
table check_cache_exist {
    reads {
        nc_hash_key.hash_key: exact;
    }
    actions {
        check_cache_exist_act;
    }
    size: NUM_CACHE;
}

register cache_valid_reg {
    width: 1;
    instance_count: NUM_CACHE;
}

action check_cache_valid_act() {
    register_read(nc_cache_md.cache_valid, cache_valid_reg, nc_cache_md.cache_index);
}
table check_cache_valid {
    actions {
        check_cache_valid_act;
    }
    //default_action: check_cache_valid_act;
}

action set_cache_valid_act() {
    register_write(cache_valid_reg, nc_cache_md.cache_index, 1);
}
table set_cache_valid {
    actions {
        set_cache_valid_act;
    }
    //default_action: set_cache_valid_act;
}

control process_cache {
    apply (get_hash_key);
    apply (check_cache_exist);
    if (nc_cache_md.cache_exist == 1) {
        if (nc_hdr.op == NC_READ_REQUEST) {
            apply (check_cache_valid);
        }
        else if (nc_hdr.op == NC_UPDATE_REPLY) {
            apply (set_cache_valid);
        }
    }
}
