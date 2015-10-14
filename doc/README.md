# Aerospike Telemetry Agent Documentation

The Aerospike Telemetry Agent collects anonymized usage statistics from an Aerospike server running on the same machine and forwards the data so obtained to Aerospike.

## Theory of Operation

The usage statistics are obtained via sending various Info. commands to the Aerospike server on its service port. The Aerospike server's service port is determined by parsing the Aerospike server configuration file, which must be provided as the value of the `config-file` property in the `[asd]` section of the Telemetry Agent configuration file. Some basic system-level statistics are also obtained from the host machine.

## Running the Telemetry Agent

1). Use Git to clone the `aerospike-telemetry-agent` repository.

2). `cd aerospike-telemetry-agent`

3). You may run `python ./telemetry.py --help` for usage:

```
$ python ./telemetry.py --help
Usage: ./telemetry.py [options] <ConfigFile> [<Service Action for Daemon Mode: (start|stop|restart|status)>]

Options:
  -h, --help            show this help message and exit
  --set-email=<EMAIL>   Set email address.
  --set-loglevel=<LOGLEVEL>
                        Set log level.
  --set-logfile=<LOGFILE>
                        Set log file.
  --set-frequency=<FREQUENCY>
                        Set logging frequency.
  --disable             Disable Telemetry Agent. (Requires agent restart to
                        take effect.)
  --enable              Enable Telemetry Agent. (Requires agent restart to
                        take effect.)
```

4). The single required argument is the Telemetry Agent configuration file.

For reference purposes, a example configuration file is provided as `telemetry_sample.conf`. (The 'real' generally comes from the Aerospike server source code tree.)

5). You may supply a command-line option to edit the configuration file.

Example usage:

```
$ python ./telemetry.py telemetry.conf --set-logfile=out
```

6). Otherwise, you must supply a service action (`start`, `stop`, `restart`, or `status`) for running the Telemetry Agent as a daemon.

Example usage:

```
$ python ./telemetry.py telemetry.conf start
```

## Configuration

The Telemetry Agent uses the parameters present in the configuration file. These parameters can be changed by directly editing the configuration file or by using the command line tool as detailed in the usage output above.

A sample development configuration file might look like:

```
[asd]
config-file = /etc/aerospike/aerospike.conf

[logging]
logfile = out
loglevel = debug

[main]
disable = false
frequency = 600
home-url = http://info.prod.aerospike.com
email =
user = aerospike
```

## Disabling/Enabling the Telemetry Agent

There are two ways to disable/enable the Telemetry Agent:

1). Directly edit the configuration file.

 When ASD is installed via a DEB or RPM package, the configuration file is stored as: `/etc/aerospike/telemetry.conf`.

To disable (or enable) the agent, set the `disable` value in the file to `true` (or `false`.)

2). Use the Telemetry Agent command line interface.

When ASD is installed via a DEB or RPM package, the main Telemetry Agent script is stored as: `/opt/aerospike/telemetry/telemetry.py`.

To disable (or enable) the Telemetry Agent run:

	$ python /opt/aerospike/telemetry/telemetry.py --disable

or

	$ python /opt/aerospike/telemetry/telemetry.py --enable

Both methods require the the user to restart Aerospike, or just the Telemetry Agent, i.e.:

	$ service aerospike restart

or

	$ service aerospike_telemetry restart

for the change to take effect.

## Data Format

The following is an example of the format of the data sent from the Telemetry Agent to Aerospike:

	{ 
	  'telemetry-agent-version': '1.0.0',
	  'loglevel': 'info',
	  'namespaces': ['test', 'bar'],
	  'node': '3001:dc64b31e530f15b99c4184b855c3c582',
	  'queries': { 'sindex': '',
	               'sindexes': { },
	               'throughput': 'query:22:26:11-GMT,ops/sec;22:26:21,0.0;'},
	  'service': '70b9a5bb72a71781513bc7047a8e1a12b9822c96704bf76f1733fcbf90b56129',
	  'services': 'd41d8cd98f00b204e9800998ecf8427e',
	  'statistics': { 'aggr_scans_failed': '0',
	                  'aggr_scans_succeeded': '0',
	                  'basic_scans_failed': '0',
	                  'basic_scans_succeeded': '0',
	                  'batch_errors': '0',
	                  'batch_index_complete': '0',
	                  'batch_index_errors': '0',
	                  'batch_index_initiate': '0',
	                  'batch_index_queue': '0:0,0:0,0:0,0:0',
	                  'batch_index_timeout': '0',
	                  'batch_index_unused_buffers': '0',
	                  'batch_initiate': '0',
	                  'batch_queue': '0',
	                  'batch_timeout': '0',
	                  'batch_tree_count': '0',
	                  'client_connections': '3',
	                  'cluster_integrity': 'true',
	                  'cluster_key': '61E015A6441128AF',
	                  'cluster_size': '1',
	                  'data-used-bytes-memory': '0',
	                  'delete_queue': '0',
	                  'err_duplicate_proxy_request': '0',
	                  'err_out_of_space': '0',
	                  'err_replica_non_null_node': '0',
	                  'err_replica_null_node': '0',
	                  'err_rw_cant_put_unique': '0',
	                  'err_rw_pending_limit': '0',
	                  'err_rw_request_not_found': '0',
	                  'err_storage_queue_full': '0',
	                  'err_sync_copy_null_master': '0',
	                  'err_sync_copy_null_node': '0',
	                  'err_tsvc_requests': '0',
	                  'err_tsvc_requests_timeout': '0',
	                  'err_write_fail_bin_exists': '0',
	                  'err_write_fail_bin_name': '0',
	                  'err_write_fail_bin_not_found': '0',
	                  'err_write_fail_forbidden': '0',
	                  'err_write_fail_generation': '0',
	                  'err_write_fail_generation_xdr': '0',
	                  'err_write_fail_incompatible_type': '0',
	                  'err_write_fail_key_exists': '0',
	                  'err_write_fail_key_mismatch': '0',
	                  'err_write_fail_not_found': '0',
	                  'err_write_fail_noxdr': '0',
	                  'err_write_fail_parameter': '0',
	                  'err_write_fail_prole_delete': '0',
	                  'err_write_fail_prole_generation': '0',
	                  'err_write_fail_prole_unknown': '0',
	                  'err_write_fail_record_too_big': '0',
	                  'err_write_fail_unknown': '0',
	                  'fabric_msgs_rcvd': '0',
	                  'fabric_msgs_sent': '0',
	                  'free-pct-disk': '0',
	                  'free-pct-memory': '100',
	                  'heartbeat_received_foreign': '0',
	                  'heartbeat_received_self': '140057',
	                  'index-used-bytes-memory': '0',
	                  'info_queue': '0',
	                  'migrate_msgs_recv': '0',
	                  'migrate_msgs_sent': '0',
	                  'migrate_num_incoming_accepted': '0',
	                  'migrate_num_incoming_refused': '0',
	                  'migrate_progress_recv': '0',
	                  'migrate_progress_send': '0',
	                  'migrate_rx_objs': '0',
	                  'migrate_tx_objs': '0',
	                  'objects': '0',
	                  'ongoing_write_reqs': '0',
	                  'partition_absent': '0',
	                  'partition_actual': '8192',
	                  'partition_desync': '0',
	                  'partition_object_count': '0',
	                  'partition_ref_count': '8192',
	                  'partition_replica': '0',
	                  'paxos_principal': 'def2c591e4c794b850f27da87c92fb74',
	                  'proxy_action': '0',
	                  'proxy_in_progress': '0',
	                  'proxy_initiate': '0',
	                  'proxy_retry': '0',
	                  'proxy_retry_new_dest': '0',
	                  'proxy_retry_q_full': '0',
	                  'proxy_retry_same_dest': '0',
	                  'proxy_unproxy': '0',
	                  'query_abort': '0',
	                  'query_agg': '0',
	                  'query_agg_abort': '0',
	                  'query_agg_avg_rec_count': '0',
	                  'query_agg_err': '0',
	                  'query_agg_success': '0',
	                  'query_avg_rec_count': '0',
	                  'query_fail': '0',
	                  'query_long_queue_full': '0',
	                  'query_long_queue_size': '0',
	                  'query_long_running': '0',
	                  'query_lookup_abort': '0',
	                  'query_lookup_avg_rec_count': '0',
	                  'query_lookup_err': '0',
	                  'query_lookup_success': '0',
	                  'query_lookups': '0',
	                  'query_reqs': '0',
	                  'query_short_queue_full': '0',
	                  'query_short_queue_size': '0',
	                  'query_short_running': '0',
	                  'query_success': '0',
	                  'query_tracked': '0',
	                  'queue': '0',
	                  'read_dup_prole': '0',
	                  'reaped_fds': '0',
	                  'record_locks': '0',
	                  'record_refs': '0',
	                  'rw_err_ack_badnode': '0',
	                  'rw_err_ack_internal': '0',
	                  'rw_err_ack_nomatch': '0',
	                  'rw_err_dup_cluster_key': '0',
	                  'rw_err_dup_internal': '0',
	                  'rw_err_dup_send': '0',
	                  'rw_err_write_cluster_key': '0',
	                  'rw_err_write_internal': '0',
	                  'rw_err_write_send': '0',
	                  'scans_active': '0',
	                  'sindex-used-bytes-memory': '0',
	                  'sindex_gc_activity_dur': '0',
	                  'sindex_gc_garbage_cleaned': '0',
	                  'sindex_gc_garbage_found': '0',
	                  'sindex_gc_inactivity_dur': '0',
	                  'sindex_gc_list_creation_time': '0',
	                  'sindex_gc_list_deletion_time': '0',
	                  'sindex_gc_locktimedout': '0',
	                  'sindex_gc_objects_validated': '0',
	                  'sindex_ucgarbage_found': '0',
	                  'stat_cluster_key_err_ack_dup_trans_reenqueue': '0',
	                  'stat_cluster_key_err_ack_rw_trans_reenqueue': '0',
	                  'stat_cluster_key_partition_transaction_queue_count': '0',
	                  'stat_cluster_key_prole_retry': '0',
	                  'stat_cluster_key_regular_processed': '0',
	                  'stat_cluster_key_trans_to_proxy_retry': '0',
	                  'stat_cluster_key_transaction_reenqueue': '0',
	                  'stat_delete_success': '0',
	                  'stat_deleted_set_objects': '0',
	                  'stat_duplicate_operation': '0',
	                  'stat_evicted_objects': '0',
	                  'stat_evicted_objects_time': '0',
	                  'stat_evicted_set_objects': '0',
	                  'stat_expired_objects': '0',
	                  'stat_ldt_proxy': '0',
	                  'stat_nsup_deletes_not_shipped': '0',
	                  'stat_proxy_errs': '0',
	                  'stat_proxy_reqs': '0',
	                  'stat_proxy_reqs_xdr': '0',
	                  'stat_proxy_success': '0',
	                  'stat_read_errs_notfound': '0',
	                  'stat_read_errs_other': '0',
	                  'stat_read_reqs': '0',
	                  'stat_read_reqs_xdr': '0',
	                  'stat_read_success': '0',
	                  'stat_rw_timeout': '0',
	                  'stat_slow_trans_queue_batch_pop': '0',
	                  'stat_slow_trans_queue_pop': '0',
	                  'stat_slow_trans_queue_push': '0',
	                  'stat_write_errs': '0',
	                  'stat_write_errs_notfound': '0',
	                  'stat_write_errs_other': '0',
	                  'stat_write_reqs': '0',
	                  'stat_write_reqs_xdr': '0',
	                  'stat_write_success': '0',
	                  'stat_xdr_pipe_miss': '0',
	                  'stat_xdr_pipe_writes': '0',
	                  'stat_zero_bin_records': '0',
	                  'storage_defrag_corrupt_record': '0',
	                  'sub-records': '0',
	                  'system_free_mem_pct': '75',
	                  'system_swapping': 'false',
	                  'total-bytes-disk': '0',
	                  'total-bytes-memory': '8589934592',
	                  'transactions': '7473',
	                  'tree_count': '0',
	                  'udf_bg_scans_failed': '0',
	                  'udf_bg_scans_succeeded': '0',
	                  'udf_delete_err_others': '0',
	                  'udf_delete_reqs': '0',
	                  'udf_delete_success': '0',
	                  'udf_lua_errs': '0',
	                  'udf_query_rec_reqs': '0',
	                  'udf_read_errs_other': '0',
	                  'udf_read_reqs': '0',
	                  'udf_read_success': '0',
	                  'udf_replica_writes': '0',
	                  'udf_scan_rec_reqs': '0',
	                  'udf_write_err_others': '0',
	                  'udf_write_reqs': '0',
	                  'udf_write_success': '0',
	                  'uptime': '21277',
	                  'used-bytes-disk': '0',
	                  'used-bytes-memory': '0',
	                  'waiting_transactions': '0',
	                  'write_master': '0',
	                  'write_prole': '0'},
	  'storage': { 'bar': { 'allow-nonxdr-writes': 'true',
	                        'allow-xdr-writes': 'true',
	                        'allow_versions': 'false',
	                        'available-bin-names': '32768',
	                        'cold-start-evict-ttl': '4294967295',
	                        'conflict-resolution-policy': 'generation',
	                        'current-time': '174867986',
	                        'data-used-bytes-memory': '0',
	                        'default-ttl': '2592000',
	                        'disallow-null-setname': 'false',
	                        'enable-xdr': 'false',
	                        'evict-tenths-pct': '5',
	                        'evicted-objects': '0',
	                        'expired-objects': '0',
	                        'free-pct-memory': '100',
	                        'high-water-disk-pct': '50',
	                        'high-water-memory-pct': '60',
	                        'hwm-breached': 'false',
	                        'index-used-bytes-memory': '0',
	                        'ldt-enabled': 'false',
	                        'ldt-page-size': '8192',
	                        'master-objects': '0',
	                        'master-sub-objects': '0',
	                        'max-ttl': '0',
	                        'max-void-time': '0',
	                        'memory-size': '4294967296',
	                        'non-expirable-objects': '0',
	                        'ns-forward-xdr-writes': 'false',
	                        'nsup-cycle-duration': '0',
	                        'nsup-cycle-sleep-pct': '0',
	                        'objects': '0',
	                        'prole-objects': '0',
	                        'prole-sub-objects': '0',
	                        'read-consistency-level-override': 'off',
	                        'repl-factor': '1',
	                        'set-deleted-objects': '0',
	                        'set-evicted-objects': '0',
	                        'sets-enable-xdr': 'true',
	                        'sindex-used-bytes-memory': '0',
	                        'single-bin': 'false',
	                        'stop-writes': 'false',
	                        'stop-writes-pct': '90',
	                        'sub-objects': '0',
	                        'total-bytes-memory': '4294967296',
	                        'type': 'memory',
	                        'used-bytes-memory': '0',
	                        'write-commit-level-override': 'off'},
	               'test': { 'allow-nonxdr-writes': 'true',
	                         'allow-xdr-writes': 'true',
	                         'allow_versions': 'false',
	                         'available-bin-names': '32768',
	                         'cold-start-evict-ttl': '4294967295',
	                         'conflict-resolution-policy': 'generation',
	                         'current-time': '174867986',
	                         'data-used-bytes-memory': '0',
	                         'default-ttl': '2592000',
	                         'disallow-null-setname': 'false',
	                         'enable-xdr': 'false',
	                         'evict-tenths-pct': '5',
	                         'evicted-objects': '0',
	                         'expired-objects': '0',
	                         'free-pct-memory': '100',
	                         'high-water-disk-pct': '50',
	                         'high-water-memory-pct': '60',
	                         'hwm-breached': 'false',
	                         'index-used-bytes-memory': '0',
	                         'ldt-enabled': 'false',
	                         'ldt-page-size': '8192',
	                         'master-objects': '0',
	                         'master-sub-objects': '0',
	                         'max-ttl': '0',
	                         'max-void-time': '0',
	                         'memory-size': '4294967296',
	                         'non-expirable-objects': '0',
	                         'ns-forward-xdr-writes': 'false',
	                         'nsup-cycle-duration': '0',
	                         'nsup-cycle-sleep-pct': '0',
	                         'objects': '0',
	                         'prole-objects': '0',
	                         'prole-sub-objects': '0',
	                         'read-consistency-level-override': 'off',
	                         'repl-factor': '1',
	                         'set-deleted-objects': '0',
	                         'set-evicted-objects': '0',
	                         'sets-enable-xdr': 'true',
	                         'sindex-used-bytes-memory': '0',
	                         'single-bin': 'false',
	                         'stop-writes': 'false',
	                         'stop-writes-pct': '90',
	                         'sub-objects': '0',
	                         'total-bytes-memory': '4294967296',
	                         'type': 'memory',
	                         'used-bytes-memory': '0',
	                         'write-commit-level-override': 'off'}}
	}
