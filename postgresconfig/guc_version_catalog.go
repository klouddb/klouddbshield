package postgresconfig

// Adjacent-major GUC catalog for PostgreSQL 15–18.
// Source: https://pgconfig.rustprooflabs.com/param/change/{from}/{to}
// Any pair (15↔18, 16↔18, 18↔16, …) is composed from these hops.

// gucVersionHop is the set of parameter changes when upgrading from → to (adjacent majors).
type gucVersionHop struct {
	From    int
	To      int
	New     []string
	Removed []string
	// Updated lists GUCs whose default (or type) changed on this hop.
	Updated []string
}

// Ordered ascending hops covering majors 15–18.
var gucVersionHops = []gucVersionHop{
	{
		From: 15, To: 16,
		New: []string{
			"createrole_self_grant",
			"debug_io_direct",
			"debug_logical_replication_streaming",
			"debug_parallel_query",
			"enable_presorted_aggregate",
			"gss_accept_delegation",
			"icu_validation_level",
			"max_parallel_apply_workers_per_subscription",
			"reserved_connections",
			"scram_iterations",
			"send_abort_for_crash",
			"send_abort_for_kill",
			"vacuum_buffer_usage_limit",
		},
		Removed: []string{
			"force_parallel_mode",
			"promote_trigger_file",
			"vacuum_defer_cleanup_age",
		},
	},
	{
		From: 16, To: 17,
		New: []string{
			"allow_alter_system",
			"commit_timestamp_buffers",
			"enable_group_by_reordering",
			"event_triggers",
			"io_combine_limit",
			"max_notify_queue_pages",
			"multixact_member_buffers",
			"multixact_offset_buffers",
			"notify_buffers",
			"restrict_nonsystem_relation_kind",
			"serializable_buffers",
			"subtransaction_buffers",
			"summarize_wal",
			"synchronized_standby_slots",
			"sync_replication_slots",
			"trace_connection_negotiation",
			"transaction_buffers",
			"transaction_timeout",
			"wal_summary_keep_time",
		},
		Removed: []string{
			"db_user_namespace",
			"old_snapshot_threshold",
			"trace_recovery_messages",
		},
		Updated: []string{
			"vacuum_buffer_usage_limit",
		},
	},
	{
		From: 17, To: 18,
		New: []string{
			"autovacuum_vacuum_max_threshold",
			"autovacuum_worker_slots",
			"enable_distinct_reordering",
			"enable_self_join_elimination",
			"extension_control_path",
			"file_copy_method",
			"idle_replication_slot_timeout",
			"io_max_combine_limit",
			"io_max_concurrency",
			"io_method",
			"io_workers",
			"log_lock_failures",
			"max_active_replication_origins",
			"md5_password_warnings",
			"oauth_validator_libraries",
			"ssl_groups",
			"ssl_tls13_ciphers",
			"track_cost_delay_timing",
			"vacuum_max_eager_freeze_failure_rate",
			"vacuum_truncate",
		},
		Removed: []string{
			"ssl_ecdh_curve",
		},
		Updated: []string{
			"effective_io_concurrency",
			"log_connections",
			"maintenance_io_concurrency",
		},
	},
}

// SupportedGucMajorVersions is the inclusive major range covered by the catalog.
var SupportedGucMajorVersions = []int{15, 16, 17, 18}
