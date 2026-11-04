package model

// PgSettings is the log_line_prefix and log_connections pair. The prefix comes from args, not the database.
type PgSettings struct {
	LogLinePrefix  string `json:"log_line_prefix"`
	LogConnections bool   `json:"log_connections"`
}
