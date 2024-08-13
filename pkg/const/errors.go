package cons

const (
	Err_PostgresConfig_Missing        = "Please check the config file /etc/klouddbshield/kshieldconfig.toml. You need to populate it with your dbname,username etc.. before using this utility. For additional details please check github readme."
	Err_MysqlConfig_Missing           = "Please check the config file /etc/klouddbshield/kshieldconfig.toml . You need to populate either mysql or postgres at a time. For additional details please check github readme."
	Err_OldversionSuggestion_Postgres = "In older version we used [database] label and in current version we are changing it to [mysql] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme."
	Err_OldversionSuggestion_Mysql    = "In older version we used [database] label and in current version we are changing it to [postgres] and kindly update your kshieldconfig file(/etc/klouddbshield/kshieldconfig.toml) - See sample entry in readme."
)
