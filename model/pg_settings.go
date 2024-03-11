package model

// Logline prefix is required from args. not reading that from database
type PgSettings struct {
	LogLinePrefix  string `json:"log_line_prefix"`
	LogConnections bool   `json:"log_connections"`
}
