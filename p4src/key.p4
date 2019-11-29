action write_key_1_act() {
    register_write(key_1_reg, nc_cache_md.cache_index, nc_hdr.key_1);
}
action write_key_2_act() {
    register_write(key_2_reg, nc_cache_md.cache_index, nc_hdr.key_2);
}
action write_key_3_act() {
    register_write(key_3_reg, nc_cache_md.cache_index, nc_hdr.key_3);
}
action write_key_4_act() {
    register_write(key_4_reg, nc_cache_md.cache_index, nc_hdr.key_4);
}
table write_key_1 {
    actions {
        write_key_1_act;
    }
}
table write_key_2 {
    actions {
        write_key_2_act;
    }
}
table write_key_3 {
    actions {
        write_key_3_act;
    }
}
table write_key_4 {
    actions {
        write_key_4_act;
    }
}

control process_key {
    if (nc_hdr.op == NC_UPDATE_REPLY and nc_cache_md.cache_exist == 0) {
        apply (write_key_1);
        apply (write_key_2);
        apply (write_key_3);
        apply (write_key_4);
        apply (check_cache_exist2)
    }
}
