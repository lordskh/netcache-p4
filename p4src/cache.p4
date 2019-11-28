header_type nc_cache_md_t {
    fields {
        cache_exist: 1;
        cache_index: 32;
        cache_valid: 1;
    }
}
metadata nc_cache_md_t nc_cache_md;

header_type nc_key_md_t {
    fields {
        key_1: 32;
        key_2: 32;
        key_3: 32;
        key_4: 32;
    }
}
metadata nc_key_md_t nc_key_md;

register cache_exist_reg {
    width: 1;
    instance_count: NUM_CACHE;
}

register key_1_reg {
    width: 32;
    instance_count: NUM_CACHE;
}

register key_2_reg {
    width: 32;
    instance_count: NUM_CACHE;
}

register key_3_reg {
    width: 32;
    instance_count: NUM_CACHE;
}

register key_4_reg {
    width: 32;
    instance_count: NUM_CACHE;
}

field_list hk_hash_fields {
    nc_hdr.key_1;
    nc_hdr.key_2;
    nc_hdr.key_3;
    nc_hdr.key_4;
}
field_list_calculation key_hash {
    input {
        hk_hash_fields;
    }
    algorithm : crc32;
    output_width : 32;
}

action check_cache_exist_act() {
    modify_field_with_hash_based_offset(nc_cache_md.cache_index, 0, key_hash, NUM_CACHE);
    register_read(nc_cache_md.cache_exist, cache_exist_reg, nc_cache_md.cache_index);
}
table check_cache_exist {
    actions {
        check_cache_exist_act;
    }
    size: NUM_CACHE;
}

action load_key_act() {
    register_read(nc_key_md.key_1, key_1_reg, nc_cache_md.cache_index);
    register_read(nc_key_md.key_2, key_2_reg, nc_cache_md.cache_index);
    register_read(nc_key_md.key_3, key_3_reg, nc_cache_md.cache_index);
    register_read(nc_key_md.key_4, key_4_reg, nc_cache_md.cache_index);
}
table load_key {
    actions {
        load_key_act;
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

action set_cache_exist_act() {
    register_write(cache_exist_reg, nc_cache_md.cache_index, 1);
}
table set_cache_exist {
    actions {
        set_cache_exist_act;
    }
    //default_action: set_cache_valid_act;
}

action set_collision_act() {
    modify_field (nc_cache_md.cache_exist, 0);
}
table set_collision {
    actions {
        set_collision_act;
    }
    //default_action: set_cache_valid_act;
}

control process_cache {
    apply (check_cache_exist);
    if (nc_cache_md.cache_exist == 1) {
        apply (load_key);
        if (nc_hdr.key_1 == nc_key_md.key_1 and nc_hdr.key_2 == nc_key_md.key_2 and nc_hdr.key_3 == nc_key_md.key_3 and nc_hdr.key_4 == nc_key_md.key_4) {
            if (nc_hdr.op == NC_READ_REQUEST) {
                apply (check_cache_valid);
            }
            else if (nc_hdr.op == NC_UPDATE_REPLY) {
                apply (set_cache_valid);
            }
        }
        else {
            apply (set_collision);
        }
    } else {
        if (nc_hdr.op == NC_UPDATE_REPLY) {
            apply (set_cache_exist);
            apply (set_cache_valid);
        }
    }
}
