/*
 * File name: sflowtool_ddos_ext.h
 *
 * Copyright(C) 2007-2014, A10 Networks Inc. All rights reserved.
 * Software for all A10 products contain trade secrets and confidential
 * information of A10 Networks and its subsidiaries and may not be
 * disclosed, copied, reproduced or distributed to anyone outside of
 * A10 Networks without prior written consent of A10 Networks, Inc.
 */
/*
 * File name: sflow_ddos_ext.h
 *
 * Copyright(C) 2007-2014, A10 Networks Inc. All rights reserved.
 * Software for all A10 products contain trade secrets and confidential
 * information of A10 Networks and its subsidiaries and may not be
 * disclosed, copied, reproduced or distributed to anyone outside of
 * A10 Networks without prior written consent of A10 Networks, Inc.
 */

#ifndef _SFLOW_DDOS_EXT_H_
#define _SFLOW_DDOS_EXT_H_

#include "sflowtool_ddos_ext_v1.h"

#include <sys/types.h>

/* Older sflow counter blocks */
typedef struct sflow_ddos_packet_counters_v1                    sflow_ddos_packet_counters_t;
typedef struct sflow_ddos_l4_counters_v1                        sflow_ddos_l4_counters_t;
typedef struct sflow_ddos_tcp_basic_counter_dir_v1              sflow_ddos_tcp_basic_counter_dir_t;
typedef struct sflow_ddos_tcp_basic_counters_v1                 sflow_ddos_tcp_basic_counters_t;
typedef struct sflow_ddos_tcp_stateful_handshake_counters_v1    sflow_ddos_tcp_stateful_handshake_counters_t;
typedef struct sflow_ddos_tcp_stateful_close_counters_v1        sflow_ddos_tcp_stateful_close_counters_t;
typedef struct sflow_ddos_tcp_stateful_counters_v1              sflow_ddos_tcp_stateful_counters_t;
typedef struct sflow_ddos_http_counters_v1                      sflow_ddos_http_counters_t;
typedef struct sflow_ddos_entry_map_v1                          sflow_ddos_entry_map_t;
typedef struct sflow_ddos_l4_global_counters_v1                 sflow_ddos_l4_global_counters_t;
typedef struct sflow_ddos_l4_global_counters_2_9_x              sflow_ddos_l4_global_counters_2_9_x_t;
typedef struct sflow_ddos_http_ext_counters_v1                  sflow_ddos_http_ext_counters_t;
typedef struct sflow_ddos_http_ext_counters_2_9_x               sflow_ddos_http_ext_counters_2_9_x_t;

/* 3.1 sflow counter blocks */
typedef struct sflow_ddos_l4_tcp_stats_v1                       sflow_ddos_l4_tcp_stats_t;
typedef struct sflow_ddos_l4_udp_stats_v1                       sflow_ddos_l4_udp_stats_t;
typedef struct sflow_ddos_l4_icmp_stats_v1                      sflow_ddos_l4_icmp_stats_t;
typedef struct sflow_ddos_l4_other_stats_v1                     sflow_ddos_l4_other_stats_t;
typedef struct sflow_ddos_switch_stats_v1                       sflow_ddos_switch_stats_t;
typedef struct sflow_ddos_sess_stats_v1                         sflow_ddos_sess_stats_t;
typedef struct sflow_ddos_sync_stats_v1                         sflow_ddos_sync_stats_t;
typedef struct sflow_ddos_tunnel_stats_v1                       sflow_ddos_tunnel_stats_t;
typedef struct sflow_ddos_ssl_l4_stats_v1                       sflow_ddos_ssl_l4_t;
typedef struct sflow_ddos_table_stats_v1                        sflow_ddos_table_stats_t;
typedef struct sflow_ddos_long_stats_v1                         sflow_ddos_long_stats_t;
typedef struct sflow_ddos_brief_stats_v1                        sflow_ddos_brief_stats_t;
typedef struct sflow_ddos_dns_stats_v1                          sflow_ddos_dns_stats_t;         // in use
typedef struct sflow_ddos_fpga_anomaly_drop_counters_v1         sflow_ddos_anomaly_counters_t;

// T2 counters:
typedef struct sflow_ddos_ind_value_v1                      sflow_ddos_ind_value_t;
typedef struct sflow_ddos_dst_udp_indicators_v1             sflow_ddos_dst_udp_indicators_t;
typedef struct sflow_ddos_dst_tcp_indicators_v1             sflow_ddos_dst_tcp_indicators_t;
typedef struct sflow_ddos_dst_icmp_indicators_v1            sflow_ddos_dst_icmp_indicators_t;
typedef struct sflow_ddos_dst_other_indicators_v1           sflow_ddos_dst_other_indicators_t;
typedef struct sflow_ddos_dst_indicators_v1                 sflow_ddos_dst_indicators_t;
typedef struct sflow_ddos_limit_result_stat_v1              sflow_ddos_limit_result_stat_t;
typedef struct sflow_ddos_limit_app_stat_v1                 sflow_ddos_limit_app_stat_t;        // in use
typedef struct sflow_ddos_limit_proto_stat_v1               sflow_ddos_limit_proto_stat_t;      // in use
typedef struct sflow_ddos_ip_counter_common_v1              sflow_ddos_ip_counter_common_t;     // in use
typedef struct sflow_ddos_ip_counter_v1                     sflow_ddos_ip_counter_t;            // in use
typedef struct sflow_ddos_ip_counter_port_v1                sflow_ddos_ip_counter_port_t;

/* Outter most struct container */
typedef struct sflow_ddos_ip_counter_l4_v1                  sflow_ddos_ip_counter_l4_t;
typedef struct sflow_ddos_ip_counter_l4_ext_v1              sflow_ddos_ip_counter_l4_ext_t;
typedef struct sflow_ddos_ip_counter_icmp_v1                sflow_ddos_ip_counter_icmp_t;
typedef struct sflow_ddos_ip_counter_udp_v1                 sflow_ddos_ip_counter_udp_t;
typedef struct sflow_ddos_ip_counter_tcp_v1                 sflow_ddos_ip_counter_tcp_t;
typedef struct sflow_ddos_ip_counter_other_v1               sflow_ddos_ip_counter_other_t;
typedef struct sflow_ddos_ip_counter_http_v1                sflow_ddos_ip_counter_http_t;
typedef struct sflow_ddos_ip_counter_dns_v1                 sflow_ddos_ip_counter_dns_t;
typedef struct sflow_ddos_ip_counter_ssl_l4_v1              sflow_ddos_ip_counter_ssl_l4_t;

typedef struct sflow_ddos_ip_counter_l4_t2_v1               sflow_ddos_ip_counter_l4_t2_t;
typedef struct sflow_ddos_ip_counter_l4_ext_t2_v1           sflow_ddos_ip_counter_l4_ext_t2_t;
typedef struct sflow_ddos_icmp_ip_ext_counters_v1           sflow_ddos_ip_counter_icmp_t2_t;
typedef struct sflow_ddos_ip_counter_http_t2_v1             sflow_ddos_ip_counter_http_t2_t;
typedef struct sflow_ddos_ip_counter_udp_t2_v1              sflow_ddos_ip_counter_udp_t2_t;
typedef struct sflow_ddos_ip_counter_tcp_t2_v1              sflow_ddos_ip_counter_tcp_t2_t;
typedef struct sflow_ddos_ip_counter_other_t2_v1            sflow_ddos_ip_counter_other_t2_t;
typedef struct sflow_ddos_ip_counter_dns_t2_v1              sflow_ddos_ip_counter_dns_t2_t;
typedef struct sflow_ddos_ip_counter_ssl_l4_t2_v1           sflow_ddos_ip_counter_ssl_l4_t2_t;

/* The actual counter data block */
typedef struct sflow_ddos_ip_counter_l4_t2_v1               sflow_ddos_ip_counter_l4_t2_data_t;
typedef struct sflow_ddos_ip_counter_l4_ext_t2_v1           sflow_ddos_ip_counter_l4_ext_t2_data_t;
typedef struct sflow_ddos_icmp_ip_ext_counters_v1           sflow_ddos_ip_counter_icmp_t2_data_t;
typedef struct sflow_ddos_http_ip_ext_counters_v1           sflow_ddos_ip_counter_http_t2_data_t;
typedef struct sflow_ddos_udp_ip_ext_counters_v1            sflow_ddos_ip_counter_udp_t2_data_t;
typedef struct sflow_ddos_tcp_ip_ext_counters_v1            sflow_ddos_ip_counter_tcp_t2_data_t;
typedef struct sflow_ddos_other_ip_ext_counters_v1          sflow_ddos_ip_counter_other_t2_data_t;
typedef struct sflow_ddos_dns_ip_ext_counters_v1            sflow_ddos_ip_counter_dns_t2_data_t;
typedef struct sflow_ddos_ssl_l4_ip_ext_counters_v1         sflow_ddos_ip_counter_ssl_l4_t2_data_t;

struct sflow_ddos_counters {

    sflow_ddos_l4_global_counters_t l4;
    sflow_ddos_http_ext_counters_t http;
    sflow_ddos_dns_stats_t     dns;
    sflow_ddos_ip_counter_l4_t l4_perip;
    sflow_ddos_ip_counter_l4_ext_t l4_ext_perip;
    sflow_ddos_ip_counter_http_t http_perip;
    sflow_ddos_ip_counter_dns_t dns_perip;
    sflow_ddos_ip_counter_port_t port;
    sflow_ddos_ip_counter_t  entry;
    sflow_ddos_anomaly_counters_t anomaly;
    sflow_ddos_entry_map_t polling_entry_map;
    sflow_ddos_packet_counters_t  polling_packets;
    sflow_ddos_l4_counters_t polling_l4;
    sflow_ddos_tcp_basic_counters_t polling_tcp_basic;
    sflow_ddos_tcp_stateful_counters_t polling_tcp_stateful;
    sflow_ddos_http_counters_t polling_http;
    sflow_ddos_ssl_l4_t ssl_l4;
    sflow_ddos_ip_counter_ssl_l4_t ssl_l4_perip;
    sflow_ddos_l4_tcp_stats_t l4_tcp;
    sflow_ddos_l4_udp_stats_t l4_udp;
    sflow_ddos_l4_icmp_stats_t l4_icmp;
    sflow_ddos_l4_other_stats_t l4_other;
    sflow_ddos_switch_stats_t l4_switch;
    sflow_ddos_sess_stats_t l4_session;
    sflow_ddos_sync_stats_t l4_sync;
    sflow_ddos_tunnel_stats_t l4_tunnel;
    sflow_ddos_table_stats_t entry_table;
    sflow_ddos_brief_stats_t ddos_brief_stats;
    sflow_ddos_long_stats_t  ddos_long_stats;
    sflow_ddos_ip_counter_icmp_t icmp_perip;
    sflow_ddos_ip_counter_udp_t udp_perip;
    sflow_ddos_ip_counter_tcp_t tcp_perip;
    sflow_ddos_ip_counter_other_t other_perip;

    sflow_ddos_dst_indicators_t ddos_dst_indicators;
    sflow_ddos_dst_tcp_indicators_t ddos_dst_tcp_indicators;
    sflow_ddos_dst_udp_indicators_t ddos_dst_udp_indicators;
    sflow_ddos_dst_icmp_indicators_t ddos_dst_icmp_indicators;
    sflow_ddos_dst_other_indicators_t ddos_dst_other_indicators;
};

#endif /* _SFLOW_DDOS_EXT_H_ */
