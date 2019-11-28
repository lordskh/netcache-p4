#include <core.p4>
#include <v1model.p4>

#define NC_PORT 8888

#define NUM_CACHE 128

#define NC_READ_REQUEST     0
#define NC_READ_REPLY       1
#define NC_HOT_READ_REQUEST 2
#define NC_WRITE_REQUEST    4
#define NC_WRITE_REPLY      5
#define NC_UPDATE_REQUEST   8
#define NC_UPDATE_REPLY     9
#define NC_UPDATE_KEY_REPLY 7

#define ETHER_TYPE_IPV4 0x0800
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17

#define HH_LOAD_WIDTH       32
#define HH_LOAD_NUM         256
#define HH_LOAD_HASH_WIDTH  8
#define HH_THRESHOLD        128
#define HH_BF_NUM           512
#define HH_BF_HASH_WIDTH    9
#define CONTROLLER_IP 0x0a000003

struct hh_bf_md_t {
    bit<16> index_1;
    bit<16> index_2;
    bit<16> index_3;
    bit<1>  bf_1;
    bit<1>  bf_2;
    bit<1>  bf_3;
}

struct nc_cache_md_t {
    bit<1>  cache_exist;
    bit<32> cache_index;
    bit<1>  cache_valid;
    bit<128> full_key;
}

struct nc_load_md_t {
    bit<16> index_1;
    bit<16> index_2;
    bit<16> index_3;
    bit<16> index_4;
    bit<32> load_1;
    bit<32> load_2;
    bit<32> load_3;
    bit<32> load_4;
}

struct reply_read_hit_info_md_t {
    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header nc_hdr_t {
    bit<8>   op;
    bit<128> key;
}

header nc_load_t {
    bit<32> load_1;
    bit<32> load_2;
    bit<32> load_3;
    bit<32> load_4;
}

header nc_value_1_t {
    bit<32> value_1_1;
    bit<32> value_1_2;
    bit<32> value_1_3;
    bit<32> value_1_4;
}

header nc_value_2_t {
    bit<32> value_2_1;
    bit<32> value_2_2;
    bit<32> value_2_3;
    bit<32> value_2_4;
}

header nc_value_3_t {
    bit<32> value_3_1;
    bit<32> value_3_2;
    bit<32> value_3_3;
    bit<32> value_3_4;
}

header nc_value_4_t {
    bit<32> value_4_1;
    bit<32> value_4_2;
    bit<32> value_4_3;
    bit<32> value_4_4;
}

header nc_value_5_t {
    bit<32> value_5_1;
    bit<32> value_5_2;
    bit<32> value_5_3;
    bit<32> value_5_4;
}

header nc_value_6_t {
    bit<32> value_6_1;
    bit<32> value_6_2;
    bit<32> value_6_3;
    bit<32> value_6_4;
}

header nc_value_7_t {
    bit<32> value_7_1;
    bit<32> value_7_2;
    bit<32> value_7_3;
    bit<32> value_7_4;
}

header nc_value_8_t {
    bit<32> value_8_1;
    bit<32> value_8_2;
    bit<32> value_8_3;
    bit<32> value_8_4;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct metadata {

    hh_bf_md_t               hh_bf_md;

    nc_cache_md_t            nc_cache_md;

    nc_load_md_t             nc_load_md;

    reply_read_hit_info_md_t reply_read_hit_info_md;
}

struct headers {

    ethernet_t   ethernet;

    ipv4_t       ipv4;

    nc_hdr_t     nc_hdr;

    nc_load_t    nc_load;

    nc_value_1_t nc_value_1;

    nc_value_2_t nc_value_2;

    nc_value_3_t nc_value_3;

    nc_value_4_t nc_value_4;

    nc_value_5_t nc_value_5;

    nc_value_6_t nc_value_6;

    nc_value_7_t nc_value_7;

    nc_value_8_t nc_value_8;

    tcp_t        tcp;

    udp_t        udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_nc_hdr {
        packet.extract(hdr.nc_hdr);
        transition select(hdr.nc_hdr.op) {
            NC_READ_REQUEST: accept;
            NC_READ_REPLY: parse_value;
            NC_HOT_READ_REQUEST: parse_nc_load;
            NC_UPDATE_REQUEST: accept;
            NC_UPDATE_REPLY: parse_value;
            default: accept;
        }
    }
    state parse_nc_load {
        packet.extract(hdr.nc_load);
        transition accept;
    }
    state parse_nc_value_1 {
        packet.extract(hdr.nc_value_1);
        transition parse_nc_value_2;
    }
    state parse_nc_value_2 {
        packet.extract(hdr.nc_value_2);
        transition parse_nc_value_3;
    }
    state parse_nc_value_3 {
        packet.extract(hdr.nc_value_3);
        transition parse_nc_value_4;
    }
    state parse_nc_value_4 {
        packet.extract(hdr.nc_value_4);
        transition parse_nc_value_5;
    }
    state parse_nc_value_5 {
        packet.extract(hdr.nc_value_5);
        transition parse_nc_value_6;
    }
    state parse_nc_value_6 {
        packet.extract(hdr.nc_value_6);
        transition parse_nc_value_7;
    }
    state parse_nc_value_7 {
        packet.extract(hdr.nc_value_7);
        transition parse_nc_value_8;
    }
    state parse_nc_value_8 {
        packet.extract(hdr.nc_value_8);
        transition parse_nc_value_9;
    }
    state parse_nc_value_9 {
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            NC_PORT: parse_nc_hdr;
            default: accept;
        }
    }
    state parse_value {
        transition parse_nc_value_1;
    }
    state start {
        transition parse_ethernet;
    }
}

register<bit<1>>(HH_BF_NUM) hh_bf_1_reg;

register<bit<1>>(HH_BF_NUM) hh_bf_2_reg;

register<bit<1>>(HH_BF_NUM) hh_bf_3_reg;

control bloom_filter(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action hh_bf_1_act() {
        hash(meta.hh_bf_md.index_1, HashAlgorithm.crc32, (bit<9>)0, { hdr.nc_hdr.key }, (bit<18>)512);
        hh_bf_1_reg.read(meta.hh_bf_md.bf_1, (bit<32>)meta.hh_bf_md.index_1);
        hh_bf_1_reg.write((bit<32>)meta.hh_bf_md.index_1, (bit<1>)1);
    }
    action hh_bf_2_act() {
        hash(meta.hh_bf_md.index_2, HashAlgorithm.csum16, (bit<9>)0, { hdr.nc_hdr.key }, (bit<18>)512);
        hh_bf_2_reg.read(meta.hh_bf_md.bf_2, (bit<32>)meta.hh_bf_md.index_2);
        hh_bf_2_reg.write((bit<32>)meta.hh_bf_md.index_2, (bit<1>)1);
    }
    action hh_bf_3_act() {
        hash(meta.hh_bf_md.index_3, HashAlgorithm.crc16, (bit<9>)0, { hdr.nc_hdr.key }, (bit<18>)512);
        hh_bf_3_reg.read(meta.hh_bf_md.bf_3, (bit<32>)meta.hh_bf_md.index_3);
        hh_bf_3_reg.write((bit<32>)meta.hh_bf_md.index_3, (bit<1>)1);
    }
    table hh_bf_1 {
        actions = {
            hh_bf_1_act;
        }
        default_action = hh_bf_1_act;
    }
    table hh_bf_2 {
        actions = {
            hh_bf_2_act;
        }
        default_action = hh_bf_2_act;
    }
    table hh_bf_3 {
        actions = {
            hh_bf_3_act;
        }
        default_action = hh_bf_3_act;
    }
    apply {
        hh_bf_1.apply();
        hh_bf_2.apply();
        hh_bf_3.apply();
    }
}

register<bit<HH_LOAD_WIDTH>>(HH_LOAD_NUM) hh_load_1_reg;

register<bit<HH_LOAD_WIDTH>>(HH_LOAD_NUM) hh_load_2_reg;

register<bit<HH_LOAD_WIDTH>>(HH_LOAD_NUM) hh_load_3_reg;

register<bit<HH_LOAD_WIDTH>>(HH_LOAD_NUM) hh_load_4_reg;

control count_min(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action hh_load_1_count_act() {
        hash(meta.nc_load_md.index_1, HashAlgorithm.crc32, (bit<8>)0, { hdr.nc_hdr.key }, (bit<16>)256);
        hh_load_1_reg.read(meta.nc_load_md.load_1, (bit<32>)meta.nc_load_md.index_1);
        hh_load_1_reg.write((bit<32>)meta.nc_load_md.index_1, (bit<32>)(meta.nc_load_md.load_1 + 32w1));
    }
    action hh_load_2_count_act() {
        hash(meta.nc_load_md.index_2, HashAlgorithm.csum16, (bit<8>)0, { hdr.nc_hdr.key }, (bit<16>)256);
        hh_load_2_reg.read(meta.nc_load_md.load_2, (bit<32>)meta.nc_load_md.index_2);
        hh_load_2_reg.write((bit<32>)meta.nc_load_md.index_2, (bit<32>)(meta.nc_load_md.load_2 + 32w1));
    }
    action hh_load_3_count_act() {
        hash(meta.nc_load_md.index_3, HashAlgorithm.crc16, (bit<8>)0, { hdr.nc_hdr.key }, (bit<16>)256);
        hh_load_3_reg.read(meta.nc_load_md.load_3, (bit<32>)meta.nc_load_md.index_3);
        hh_load_3_reg.write((bit<32>)meta.nc_load_md.index_3, (bit<32>)(meta.nc_load_md.load_3 + 32w1));
    }
    action hh_load_4_count_act() {
        hash(meta.nc_load_md.index_4, HashAlgorithm.crc32, (bit<8>)0, { hdr.nc_hdr.key }, (bit<16>)256);
        hh_load_4_reg.read(meta.nc_load_md.load_4, (bit<32>)meta.nc_load_md.index_4);
        hh_load_4_reg.write((bit<32>)meta.nc_load_md.index_4, (bit<32>)(meta.nc_load_md.load_4 + 32w1));
    }
    table hh_load_1_count {
        actions = {
            hh_load_1_count_act;
        }
        default_action = hh_load_1_count_act;
    }
    table hh_load_2_count {
        actions = {
            hh_load_2_count_act;
        }
        default_action = hh_load_2_count_act;
    }
    table hh_load_3_count {
        actions = {
            hh_load_3_count_act;
        }
        default_action = hh_load_3_count_act;
    }
    table hh_load_4_count {
        actions = {
            hh_load_4_count_act;
        }
        default_action = hh_load_4_count_act;
    }
    apply {
        hh_load_1_count.apply();
        hh_load_2_count.apply();
        hh_load_3_count.apply();
        hh_load_4_count.apply();
    }
}

control report_hot_step_1(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action clone_to_controller_act() {
        clone3(CloneType.E2E, (bit<32>)32w3, { meta.nc_load_md.load_1, meta.nc_load_md.load_2, meta.nc_load_md.load_3, meta.nc_load_md.load_4 });
    }
    table clone_to_controller {
        actions = {
            clone_to_controller_act;
        }
        default_action = clone_to_controller_act;
    }
    apply {
        clone_to_controller.apply();
    }
}

control report_hot_step_2(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action report_hot_act() {
        hdr.nc_hdr.op = NC_HOT_READ_REQUEST;
        hdr.nc_load.setValid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_load.load_1 = meta.nc_load_md.load_1;
        hdr.nc_load.load_2 = meta.nc_load_md.load_2;
        hdr.nc_load.load_3 = meta.nc_load_md.load_3;
        hdr.nc_load.load_4 = meta.nc_load_md.load_4;
        hdr.ipv4.dstAddr = CONTROLLER_IP;
    }
    table report_hot {
        actions = {
            report_hot_act;
        }
        default_action = report_hot_act;
    }
    apply {
        report_hot.apply();
    }
}

control heavy_hitter(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    count_min() count_min_0;
    bloom_filter() bloom_filter_0;
    report_hot_step_1() report_hot_step_1_0;
    report_hot_step_2() report_hot_step_2_0;
    apply {
        if (standard_metadata.instance_type == 0) {
            count_min_0.apply(hdr, meta, standard_metadata);
            if (meta.nc_load_md.load_1 > HH_THRESHOLD) {
                if (meta.nc_load_md.load_2 > HH_THRESHOLD) {
                    if (meta.nc_load_md.load_3 > HH_THRESHOLD) {
                        if (meta.nc_load_md.load_4 > HH_THRESHOLD) {
                            bloom_filter_0.apply(hdr, meta, standard_metadata);
                            if (meta.hh_bf_md.bf_1 == 0 || meta.hh_bf_md.bf_2 == 0 || meta.hh_bf_md.bf_3 == 0) {
                                report_hot_step_1_0.apply(hdr, meta, standard_metadata);
                            }
                        }
                    }
                }
            }
        } else {
            report_hot_step_2_0.apply(hdr, meta, standard_metadata);
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action ethernet_set_mac_act(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }
    table ethernet_set_mac {
        actions = {
            ethernet_set_mac_act;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
    }
    heavy_hitter() heavy_hitter_0;
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_exist != 1) {
            heavy_hitter_0.apply(hdr, meta, standard_metadata);
        }
        ethernet_set_mac.apply();
    }
}

register<bit<32>>(NUM_CACHE) key_1_reg;

register<bit<32>>(NUM_CACHE) key_2_reg;

register<bit<32>>(NUM_CACHE) key_3_reg;

register<bit<32>>(NUM_CACHE) key_4_reg;

register<bit<1>>(NUM_CACHE) cache_exist_reg;
register<bit<1>>(NUM_CACHE) cache_valid_reg;

control process_cache(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action check_cache_exist_act() {
        hash(meta.nc_cache_md.cache_index, HashAlgorithm.crc32, (bit<32>)0, {hdr.nc_hdr.key}, (bit<32>)1 << 31);
        cache_valid_reg.read(meta.nc_cache_md.cache_valid, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action check_cache_valid_act() {
        cache_valid_reg.read(meta.nc_cache_md.cache_valid, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action set_cache_valid_act() {
        cache_valid_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<1>)1);
    }
    action set_cache_exist_act() {
        cache_exist_reg.write((bit<32>)meta.nc_cache_md.cache_index, 0);
    }
    action load_key_act() {
		bit<32> key_1;
		bit<32> key_2;
		bit<32> key_3;
		bit<32> key_4;
		key_1_reg.read(key_1, (bit<32>)meta.nc_cache_md.cache_index);
		key_2_reg.read(key_2, (bit<32>)meta.nc_cache_md.cache_index);
		key_3_reg.read(key_3, (bit<32>)meta.nc_cache_md.cache_index);
		key_4_reg.read(key_4, (bit<32>)meta.nc_cache_md.cache_index);
        meta.nc_cache_md.full_key = key_1 ++ key_2 ++ key_3 ++ key_4;
    }
    table check_cache_exist {
        actions = {
            check_cache_exist_act;
        }
        default_action = check_cache_exist_act;
    }
    table check_cache_valid {
        actions = {
            check_cache_valid_act;
        }
        default_action = check_cache_valid_act;
    }
    table set_cache_valid {
        actions = {
            set_cache_valid_act;
        }
        default_action = set_cache_valid_act;
    }
    table set_cache_exist {
        actions = {
            set_cache_exist_act;
        }
        default_action = set_cache_exist_act;
    }
    table load_key {
        actions = {
            load_key_act;
        }
        default_action = load_key_act;
    }
    apply {
        check_cache_exist.apply();
        if (meta.nc_cache_md.cache_exist == 1) {
            load_key.apply();
            if (meta.nc_cache_md.full_key == hdr.nc_hdr.key) {
                if (hdr.nc_hdr.op == NC_READ_REQUEST) {
                    check_cache_valid.apply();
                } else {
                    if (hdr.nc_hdr.op == NC_UPDATE_REPLY) {
                        set_cache_valid.apply();
                    }
                }
            } else {
                meta.nc_cache_md.cache_exist = 0;
            }
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY) {
                set_cache_exist.apply();
                set_cache_valid.apply();
            }
        }
    }
}

control process_key(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action write_key_1_act() {
        key_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_hdr.key[31:0]);
    }
    action write_key_2_act() {
        key_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_hdr.key[63:32]);
    }
    action write_key_3_act() {
        key_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_hdr.key[95:64]);
    }
    action write_key_4_act() {
        key_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_hdr.key[127:96]);
    }
    table write_key_1 {
        actions = {
            write_key_1_act;
        }
        default_action = write_key_1_act;
    }
    table write_key_2 {
        actions = {
            write_key_2_act;
        }
        default_action = write_key_2_act;
    }
    table write_key_3 {
        actions = {
            write_key_3_act;
        }
        default_action = write_key_3_act;
    }
    table write_key_4 {
        actions = {
            write_key_4_act;
        }
        default_action = write_key_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 0) {
            write_key_1.apply();
            write_key_2.apply();
            write_key_3.apply();
            write_key_4.apply();
        }
    }
}

register<bit<32>>(NUM_CACHE) value_1_1_reg;

register<bit<32>>(NUM_CACHE) value_1_2_reg;

register<bit<32>>(NUM_CACHE) value_1_3_reg;

register<bit<32>>(NUM_CACHE) value_1_4_reg;

control process_value_1(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_1_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_1.setValid();
    }
    action read_value_1_1_act() {
        value_1_1_reg.read(hdr.nc_value_1.value_1_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_1_2_act() {
        value_1_2_reg.read(hdr.nc_value_1.value_1_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_1_3_act() {
        value_1_3_reg.read(hdr.nc_value_1.value_1_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_1_4_act() {
        value_1_4_reg.read(hdr.nc_value_1.value_1_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_1_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_1.setInvalid();
    }
    action write_value_1_1_act() {
        value_1_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_1.value_1_1);
    }
    action write_value_1_2_act() {
        value_1_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_1.value_1_2);
    }
    action write_value_1_3_act() {
        value_1_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_1.value_1_3);
    }
    action write_value_1_4_act() {
        value_1_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_1.value_1_4);
    }
    table add_value_header_1 {
        actions = {
            add_value_header_1_act;
        }
        default_action = add_value_header_1_act;
    }
    table read_value_1_1 {
        actions = {
            read_value_1_1_act;
        }
        default_action = read_value_1_1_act;
    }
    table read_value_1_2 {
        actions = {
            read_value_1_2_act;
        }
        default_action = read_value_1_2_act;
    }
    table read_value_1_3 {
        actions = {
            read_value_1_3_act;
        }
        default_action = read_value_1_3_act;
    }
    table read_value_1_4 {
        actions = {
            read_value_1_4_act;
        }
        default_action = read_value_1_4_act;
    }
    table remove_value_header_1 {
        actions = {
            remove_value_header_1_act;
        }
        default_action = remove_value_header_1_act;
    }
    table write_value_1_1 {
        actions = {
            write_value_1_1_act;
        }
        default_action = write_value_1_1_act;
    }
    table write_value_1_2 {
        actions = {
            write_value_1_2_act;
        }
        default_action = write_value_1_2_act;
    }
    table write_value_1_3 {
        actions = {
            write_value_1_3_act;
        }
        default_action = write_value_1_3_act;
    }
    table write_value_1_4 {
        actions = {
            write_value_1_4_act;
        }
        default_action = write_value_1_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1w1) {
            add_value_header_1.apply();
            read_value_1_1.apply();
            read_value_1_2.apply();
            read_value_1_3.apply();
            read_value_1_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1w1) {
                write_value_1_1.apply();
                write_value_1_2.apply();
                write_value_1_3.apply();
                write_value_1_4.apply();
                remove_value_header_1.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_2_1_reg;

register<bit<32>>(NUM_CACHE) value_2_2_reg;

register<bit<32>>(NUM_CACHE) value_2_3_reg;

register<bit<32>>(NUM_CACHE) value_2_4_reg;

control process_value_2(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_2_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_2.setValid();
    }
    action read_value_2_1_act() {
        value_2_1_reg.read(hdr.nc_value_2.value_2_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_2_2_act() {
        value_2_2_reg.read(hdr.nc_value_2.value_2_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_2_3_act() {
        value_2_3_reg.read(hdr.nc_value_2.value_2_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_2_4_act() {
        value_2_4_reg.read(hdr.nc_value_2.value_2_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_2_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_2.setInvalid();
    }
    action write_value_2_1_act() {
        value_2_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_2.value_2_1);
    }
    action write_value_2_2_act() {
        value_2_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_2.value_2_2);
    }
    action write_value_2_3_act() {
        value_2_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_2.value_2_3);
    }
    action write_value_2_4_act() {
        value_2_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_2.value_2_4);
    }
    table add_value_header_2 {
        actions = {
            add_value_header_2_act;
        }
        default_action = add_value_header_2_act;
    }
    table read_value_2_1 {
        actions = {
            read_value_2_1_act;
        }
        default_action = read_value_2_1_act;
    }
    table read_value_2_2 {
        actions = {
            read_value_2_2_act;
        }
        default_action = read_value_2_2_act;
    }
    table read_value_2_3 {
        actions = {
            read_value_2_3_act;
        }
        default_action = read_value_2_3_act;
    }
    table read_value_2_4 {
        actions = {
            read_value_2_4_act;
        }
        default_action = read_value_2_4_act;
    }
    table remove_value_header_2 {
        actions = {
            remove_value_header_2_act;
        }
        default_action = remove_value_header_2_act;
    }
    table write_value_2_1 {
        actions = {
            write_value_2_1_act;
        }
        default_action = write_value_2_1_act;
    }
    table write_value_2_2 {
        actions = {
            write_value_2_2_act;
        }
        default_action = write_value_2_2_act;
    }
    table write_value_2_3 {
        actions = {
            write_value_2_3_act;
        }
        default_action = write_value_2_3_act;
    }
    table write_value_2_4 {
        actions = {
            write_value_2_4_act;
        }
        default_action = write_value_2_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_2.apply();
            read_value_2_1.apply();
            read_value_2_2.apply();
            read_value_2_3.apply();
            read_value_2_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_2_1.apply();
                write_value_2_2.apply();
                write_value_2_3.apply();
                write_value_2_4.apply();
                remove_value_header_2.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_3_1_reg;

register<bit<32>>(NUM_CACHE) value_3_2_reg;

register<bit<32>>(NUM_CACHE) value_3_3_reg;

register<bit<32>>(NUM_CACHE) value_3_4_reg;

control process_value_3(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_3_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_3.setValid();
    }
    action read_value_3_1_act() {
        value_3_1_reg.read(hdr.nc_value_3.value_3_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_3_2_act() {
        value_3_2_reg.read(hdr.nc_value_3.value_3_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_3_3_act() {
        value_3_3_reg.read(hdr.nc_value_3.value_3_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_3_4_act() {
        value_3_4_reg.read(hdr.nc_value_3.value_3_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_3_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_3.setInvalid();
    }
    action write_value_3_1_act() {
        value_3_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_3.value_3_1);
    }
    action write_value_3_2_act() {
        value_3_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_3.value_3_2);
    }
    action write_value_3_3_act() {
        value_3_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_3.value_3_3);
    }
    action write_value_3_4_act() {
        value_3_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_3.value_3_4);
    }
    table add_value_header_3 {
        actions = {
            add_value_header_3_act;
        }
        default_action = add_value_header_3_act;
    }
    table read_value_3_1 {
        actions = {
            read_value_3_1_act;
        }
        default_action = read_value_3_1_act;
    }
    table read_value_3_2 {
        actions = {
            read_value_3_2_act;
        }
        default_action = read_value_3_2_act;
    }
    table read_value_3_3 {
        actions = {
            read_value_3_3_act;
        }
        default_action = read_value_3_3_act;
    }
    table read_value_3_4 {
        actions = {
            read_value_3_4_act;
        }
        default_action = read_value_3_4_act;
    }
    table remove_value_header_3 {
        actions = {
            remove_value_header_3_act;
        }
        default_action = remove_value_header_3_act;
    }
    table write_value_3_1 {
        actions = {
            write_value_3_1_act;
        }
        default_action = write_value_3_1_act;
    }
    table write_value_3_2 {
        actions = {
            write_value_3_2_act;
        }
        default_action = write_value_3_2_act;
    }
    table write_value_3_3 {
        actions = {
            write_value_3_3_act;
        }
        default_action = write_value_3_3_act;
    }
    table write_value_3_4 {
        actions = {
            write_value_3_4_act;
        }
        default_action = write_value_3_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_3.apply();
            read_value_3_1.apply();
            read_value_3_2.apply();
            read_value_3_3.apply();
            read_value_3_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_3_1.apply();
                write_value_3_2.apply();
                write_value_3_3.apply();
                write_value_3_4.apply();
                remove_value_header_3.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_4_1_reg;

register<bit<32>>(NUM_CACHE) value_4_2_reg;

register<bit<32>>(NUM_CACHE) value_4_3_reg;

register<bit<32>>(NUM_CACHE) value_4_4_reg;

control process_value_4(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_4_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_4.setValid();
    }
    action read_value_4_1_act() {
        value_4_1_reg.read(hdr.nc_value_4.value_4_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_4_2_act() {
        value_4_2_reg.read(hdr.nc_value_4.value_4_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_4_3_act() {
        value_4_3_reg.read(hdr.nc_value_4.value_4_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_4_4_act() {
        value_4_4_reg.read(hdr.nc_value_4.value_4_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_4_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_4.setInvalid();
    }
    action write_value_4_1_act() {
        value_4_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_4.value_4_1);
    }
    action write_value_4_2_act() {
        value_4_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_4.value_4_2);
    }
    action write_value_4_3_act() {
        value_4_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_4.value_4_3);
    }
    action write_value_4_4_act() {
        value_4_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_4.value_4_4);
    }
    table add_value_header_4 {
        actions = {
            add_value_header_4_act;
        }
        default_action = add_value_header_4_act;
    }
    table read_value_4_1 {
        actions = {
            read_value_4_1_act;
        }
        default_action = read_value_4_1_act;
    }
    table read_value_4_2 {
        actions = {
            read_value_4_2_act;
        }
        default_action = read_value_4_2_act;
    }
    table read_value_4_3 {
        actions = {
            read_value_4_3_act;
        }
        default_action = read_value_4_3_act;
    }
    table read_value_4_4 {
        actions = {
            read_value_4_4_act;
        }
        default_action = read_value_4_4_act;
    }
    table remove_value_header_4 {
        actions = {
            remove_value_header_4_act;
        }
        default_action = remove_value_header_4_act;
    }
    table write_value_4_1 {
        actions = {
            write_value_4_1_act;
        }
        default_action = write_value_4_1_act;
    }
    table write_value_4_2 {
        actions = {
            write_value_4_2_act;
        }
        default_action = write_value_4_2_act;
    }
    table write_value_4_3 {
        actions = {
            write_value_4_3_act;
        }
        default_action = write_value_4_3_act;
    }
    table write_value_4_4 {
        actions = {
            write_value_4_4_act;
        }
        default_action = write_value_4_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_4.apply();
            read_value_4_1.apply();
            read_value_4_2.apply();
            read_value_4_3.apply();
            read_value_4_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_4_1.apply();
                write_value_4_2.apply();
                write_value_4_3.apply();
                write_value_4_4.apply();
                remove_value_header_4.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_5_1_reg;

register<bit<32>>(NUM_CACHE) value_5_2_reg;

register<bit<32>>(NUM_CACHE) value_5_3_reg;

register<bit<32>>(NUM_CACHE) value_5_4_reg;

control process_value_5(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_5_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_5.setValid();
    }
    action read_value_5_1_act() {
        value_5_1_reg.read(hdr.nc_value_5.value_5_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_5_2_act() {
        value_5_2_reg.read(hdr.nc_value_5.value_5_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_5_3_act() {
        value_5_3_reg.read(hdr.nc_value_5.value_5_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_5_4_act() {
        value_5_4_reg.read(hdr.nc_value_5.value_5_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_5_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_5.setInvalid();
    }
    action write_value_5_1_act() {
        value_5_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_5.value_5_1);
    }
    action write_value_5_2_act() {
        value_5_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_5.value_5_2);
    }
    action write_value_5_3_act() {
        value_5_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_5.value_5_3);
    }
    action write_value_5_4_act() {
        value_5_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_5.value_5_4);
    }
    table add_value_header_5 {
        actions = {
            add_value_header_5_act;
        }
        default_action = add_value_header_5_act;
    }
    table read_value_5_1 {
        actions = {
            read_value_5_1_act;
        }
        default_action = read_value_5_1_act;
    }
    table read_value_5_2 {
        actions = {
            read_value_5_2_act;
        }
        default_action = read_value_5_2_act;
    }
    table read_value_5_3 {
        actions = {
            read_value_5_3_act;
        }
        default_action = read_value_5_3_act;
    }
    table read_value_5_4 {
        actions = {
            read_value_5_4_act;
        }
        default_action = read_value_5_4_act;
    }
    table remove_value_header_5 {
        actions = {
            remove_value_header_5_act;
        }
        default_action = remove_value_header_5_act;
    }
    table write_value_5_1 {
        actions = {
            write_value_5_1_act;
        }
        default_action = write_value_5_1_act;
    }
    table write_value_5_2 {
        actions = {
            write_value_5_2_act;
        }
        default_action = write_value_5_2_act;
    }
    table write_value_5_3 {
        actions = {
            write_value_5_3_act;
        }
        default_action = write_value_5_3_act;
    }
    table write_value_5_4 {
        actions = {
            write_value_5_4_act;
        }
        default_action = write_value_5_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_5.apply();
            read_value_5_1.apply();
            read_value_5_2.apply();
            read_value_5_3.apply();
            read_value_5_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_5_1.apply();
                write_value_5_2.apply();
                write_value_5_3.apply();
                write_value_5_4.apply();
                remove_value_header_5.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_6_1_reg;

register<bit<32>>(NUM_CACHE) value_6_2_reg;

register<bit<32>>(NUM_CACHE) value_6_3_reg;

register<bit<32>>(NUM_CACHE) value_6_4_reg;

control process_value_6(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_6_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_6.setValid();
    }
    action read_value_6_1_act() {
        value_6_1_reg.read(hdr.nc_value_6.value_6_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_6_2_act() {
        value_6_2_reg.read(hdr.nc_value_6.value_6_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_6_3_act() {
        value_6_3_reg.read(hdr.nc_value_6.value_6_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_6_4_act() {
        value_6_4_reg.read(hdr.nc_value_6.value_6_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_6_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_6.setInvalid();
    }
    action write_value_6_1_act() {
        value_6_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_6.value_6_1);
    }
    action write_value_6_2_act() {
        value_6_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_6.value_6_2);
    }
    action write_value_6_3_act() {
        value_6_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_6.value_6_3);
    }
    action write_value_6_4_act() {
        value_6_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_6.value_6_4);
    }
    table add_value_header_6 {
        actions = {
            add_value_header_6_act;
        }
        default_action = add_value_header_6_act;
    }
    table read_value_6_1 {
        actions = {
            read_value_6_1_act;
        }
        default_action = read_value_6_1_act;
    }
    table read_value_6_2 {
        actions = {
            read_value_6_2_act;
        }
        default_action = read_value_6_2_act;
    }
    table read_value_6_3 {
        actions = {
            read_value_6_3_act;
        }
        default_action = read_value_6_3_act;
    }
    table read_value_6_4 {
        actions = {
            read_value_6_4_act;
        }
        default_action = read_value_6_4_act;
    }
    table remove_value_header_6 {
        actions = {
            remove_value_header_6_act;
        }
        default_action = remove_value_header_6_act;
    }
    table write_value_6_1 {
        actions = {
            write_value_6_1_act;
        }
        default_action = write_value_6_1_act;
    }
    table write_value_6_2 {
        actions = {
            write_value_6_2_act;
        }
        default_action = write_value_6_2_act;
    }
    table write_value_6_3 {
        actions = {
            write_value_6_3_act;
        }
        default_action = write_value_6_3_act;
    }
    table write_value_6_4 {
        actions = {
            write_value_6_4_act;
        }
        default_action = write_value_6_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_6.apply();
            read_value_6_1.apply();
            read_value_6_2.apply();
            read_value_6_3.apply();
            read_value_6_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_6_1.apply();
                write_value_6_2.apply();
                write_value_6_3.apply();
                write_value_6_4.apply();
                remove_value_header_6.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_7_1_reg;

register<bit<32>>(NUM_CACHE) value_7_2_reg;

register<bit<32>>(NUM_CACHE) value_7_3_reg;

register<bit<32>>(NUM_CACHE) value_7_4_reg;

control process_value_7(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_7_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_7.setValid();
    }
    action read_value_7_1_act() {
        value_7_1_reg.read(hdr.nc_value_7.value_7_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_7_2_act() {
        value_7_2_reg.read(hdr.nc_value_7.value_7_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_7_3_act() {
        value_7_3_reg.read(hdr.nc_value_7.value_7_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_7_4_act() {
        value_7_4_reg.read(hdr.nc_value_7.value_7_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_7_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_7.setInvalid();
    }
    action write_value_7_1_act() {
        value_7_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_7.value_7_1);
    }
    action write_value_7_2_act() {
        value_7_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_7.value_7_2);
    }
    action write_value_7_3_act() {
        value_7_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_7.value_7_3);
    }
    action write_value_7_4_act() {
        value_7_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_7.value_7_4);
    }
    table add_value_header_7 {
        actions = {
            add_value_header_7_act;
        }
        default_action = add_value_header_7_act;
    }
    table read_value_7_1 {
        actions = {
            read_value_7_1_act;
        }
        default_action = read_value_7_1_act;
    }
    table read_value_7_2 {
        actions = {
            read_value_7_2_act;
        }
        default_action = read_value_7_2_act;
    }
    table read_value_7_3 {
        actions = {
            read_value_7_3_act;
        }
        default_action = read_value_7_3_act;
    }
    table read_value_7_4 {
        actions = {
            read_value_7_4_act;
        }
        default_action = read_value_7_4_act;
    }
    table remove_value_header_7 {
        actions = {
            remove_value_header_7_act;
        }
        default_action = remove_value_header_7_act;
    }
    table write_value_7_1 {
        actions = {
            write_value_7_1_act;
        }
        default_action = write_value_7_1_act;
    }
    table write_value_7_2 {
        actions = {
            write_value_7_2_act;
        }
        default_action = write_value_7_2_act;
    }
    table write_value_7_3 {
        actions = {
            write_value_7_3_act;
        }
        default_action = write_value_7_3_act;
    }
    table write_value_7_4 {
        actions = {
            write_value_7_4_act;
        }
        default_action = write_value_7_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_7.apply();
            read_value_7_1.apply();
            read_value_7_2.apply();
            read_value_7_3.apply();
            read_value_7_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_7_1.apply();
                write_value_7_2.apply();
                write_value_7_3.apply();
                write_value_7_4.apply();
                remove_value_header_7.apply();
            }
        }
    }
}

register<bit<32>>(NUM_CACHE) value_8_1_reg;

register<bit<32>>(NUM_CACHE) value_8_2_reg;

register<bit<32>>(NUM_CACHE) value_8_3_reg;

register<bit<32>>(NUM_CACHE) value_8_4_reg;

control process_value_8(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_value_header_8_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
        hdr.udp.len = hdr.udp.len + 16;
        hdr.nc_value_8.setValid();
    }
    action read_value_8_1_act() {
        value_8_1_reg.read(hdr.nc_value_8.value_8_1, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_8_2_act() {
        value_8_2_reg.read(hdr.nc_value_8.value_8_2, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_8_3_act() {
        value_8_3_reg.read(hdr.nc_value_8.value_8_3, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action read_value_8_4_act() {
        value_8_4_reg.read(hdr.nc_value_8.value_8_4, (bit<32>)meta.nc_cache_md.cache_index);
    }
    action remove_value_header_8_act() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        hdr.udp.len = hdr.udp.len - 16;
        hdr.nc_value_8.setInvalid();
    }
    action write_value_8_1_act() {
        value_8_1_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_8.value_8_1);
    }
    action write_value_8_2_act() {
        value_8_2_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_8.value_8_2);
    }
    action write_value_8_3_act() {
        value_8_3_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_8.value_8_3);
    }
    action write_value_8_4_act() {
        value_8_4_reg.write((bit<32>)meta.nc_cache_md.cache_index, (bit<32>)hdr.nc_value_8.value_8_4);
    }
    table add_value_header_8 {
        actions = {
            add_value_header_8_act;
        }
        default_action = add_value_header_8_act;
    }
    table read_value_8_1 {
        actions = {
            read_value_8_1_act;
        }
        default_action = read_value_8_1_act;
    }
    table read_value_8_2 {
        actions = {
            read_value_8_2_act;
        }
        default_action = read_value_8_2_act;
    }
    table read_value_8_3 {
        actions = {
            read_value_8_3_act;
        }
        default_action = read_value_8_3_act;
    }
    table read_value_8_4 {
        actions = {
            read_value_8_4_act;
        }
        default_action = read_value_8_4_act;
    }
    table remove_value_header_8 {
        actions = {
            remove_value_header_8_act;
        }
        default_action = remove_value_header_8_act;
    }
    table write_value_8_1 {
        actions = {
            write_value_8_1_act;
        }
        default_action = write_value_8_1_act;
    }
    table write_value_8_2 {
        actions = {
            write_value_8_2_act;
        }
        default_action = write_value_8_2_act;
    }
    table write_value_8_3 {
        actions = {
            write_value_8_3_act;
        }
        default_action = write_value_8_3_act;
    }
    table write_value_8_4 {
        actions = {
            write_value_8_4_act;
        }
        default_action = write_value_8_4_act;
    }
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            add_value_header_8.apply();
            read_value_8_1.apply();
            read_value_8_2.apply();
            read_value_8_3.apply();
            read_value_8_4.apply();
        } else {
            if (hdr.nc_hdr.op == NC_UPDATE_REPLY && meta.nc_cache_md.cache_exist == 1) {
                write_value_8_1.apply();
                write_value_8_2.apply();
                write_value_8_3.apply();
                write_value_8_4.apply();
                remove_value_header_8.apply();
            }
        }
    }
}

control process_value(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action reply_read_hit_after_act() {
        hdr.ipv4.srcAddr = meta.reply_read_hit_info_md.ipv4_dstAddr;
        hdr.ipv4.dstAddr = meta.reply_read_hit_info_md.ipv4_srcAddr;
        hdr.nc_hdr.op = NC_READ_REPLY;
    }
    action reply_read_hit_before_act() {
        meta.reply_read_hit_info_md.ipv4_srcAddr = hdr.ipv4.srcAddr;
        meta.reply_read_hit_info_md.ipv4_dstAddr = hdr.ipv4.dstAddr;
    }
    table reply_read_hit_after {
        actions = {
            reply_read_hit_after_act;
        }
        default_action = reply_read_hit_after_act;
    }
    table reply_read_hit_before {
        actions = {
            reply_read_hit_before_act;
        }
        default_action = reply_read_hit_before_act;
    }
    process_value_1() process_value_1_0;
    process_value_2() process_value_2_0;
    process_value_3() process_value_3_0;
    process_value_4() process_value_4_0;
    process_value_5() process_value_5_0;
    process_value_6() process_value_6_0;
    process_value_7() process_value_7_0;
    process_value_8() process_value_8_0;
    apply {
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            reply_read_hit_before.apply();
        }
        process_value_1_0.apply(hdr, meta, standard_metadata);
        process_value_2_0.apply(hdr, meta, standard_metadata);
        process_value_3_0.apply(hdr, meta, standard_metadata);
        process_value_4_0.apply(hdr, meta, standard_metadata);
        process_value_5_0.apply(hdr, meta, standard_metadata);
        process_value_6_0.apply(hdr, meta, standard_metadata);
        process_value_7_0.apply(hdr, meta, standard_metadata);
        process_value_8_0.apply(hdr, meta, standard_metadata);
        if (hdr.nc_hdr.op == NC_READ_REQUEST && meta.nc_cache_md.cache_valid == 1) {
            reply_read_hit_after.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_egress(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    @stage(11) table ipv4_route {
        actions = {
            set_egress;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 8192;
    }
    process_cache() process_cache_0;
    process_key() process_key_0;
    process_value() process_value_0;
    apply {
        process_cache_0.apply(hdr, meta, standard_metadata);
        process_key_0.apply(hdr, meta, standard_metadata);
        process_value_0.apply(hdr, meta, standard_metadata);
        ipv4_route.apply();
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.nc_hdr);
        packet.emit(hdr.nc_load);
        packet.emit(hdr.nc_value_1);
        packet.emit(hdr.nc_value_2);
        packet.emit(hdr.nc_value_3);
        packet.emit(hdr.nc_value_4);
        packet.emit(hdr.nc_value_5);
        packet.emit(hdr.nc_value_6);
        packet.emit(hdr.nc_value_7);
        packet.emit(hdr.nc_value_8);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, hdr.udp.len, hdr.udp.srcPort, hdr.udp.dstPort, hdr.udp.len }, hdr.udp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
