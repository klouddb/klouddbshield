# KloudDB_Shield

[![GitHub Release][release-img]][release]

<!-- [![Go Report Card][report-card-img]][report-card]

[![Build Status](https://github.com/klouddb/klouddbshield/workflows/Build/badge.svg?branch=main)](https://github.com/klouddb/klouddbshield/actions) -->

[release-img]: https://img.shields.io/github/release/klouddb/klouddbshield.svg?logo=github
[release]: https://github.com/klouddb/klouddbshield/releases
[report-card-img]: https://goreportcard.com/badge/github.com/klouddb/klouddbshield
[report-card]: https://goreportcard.com/report/github.com/klouddb/klouddbshield

## Installation

##### How to run this tool on my server ?

Postgres - Please read https://klouddb.io/cis-benchmarks-for-postgres-klouddbshield-1-1/

MySQL -  Please read https://klouddb.io/releasing-first-version-of-klouddb-shield-mysql-cis-benchmarks/ 

NOTE - It works for both MySQL 8 and MySQL 5.7 (Some controls might not be applicable in 5.7) ; For some linux commands you might need root/sudo access 

You can directly download the package from [releases](https://github.com/klouddb/klouddbshield/releases) section of repo and install the package (for example - rpm for centos and deb package for Ubuntu etc..) . You also need to edit config file after installing the package(see above mentioned blog post for detailed walkthrough)


```bash
# Centos
$ rpm -i <ciscollector file>.rpm

# Debian
$ dpkg -i <ciscollector file>.deb

Usage of ciscollector:
  -r    Run
  -version
        Print version
$ ciscollector -r
Section 1  - Operating system          - 1/6  - 16.67%
Section 2  - Installation and Planning - 4/10 - 40.00%
Section 3  - File Permissions          - 2/9  - 22.22%
Section 4  - General                   - 5/7  - 71.43%
Section 6  - Auditing and Logging      - 2/3  - 66.67%
Section 7  - Authentication            - 4/6  - 66.67%
Section 8  - Network                   - 0/2  - 0.00%
Section 9  - Replication               - 0/2  - 0.00%
Overall Score - 18/45 - 40.00%
mysqlsecreport.json file generated
```

## How to run locally(without installing a package) ?

Install and run locally the server

```bash
$ go build -o ./ciscollector ./cmd/ciscollector
# Edit kshieldconfig.toml at path /etc/klouddbshield/kshieldconfig.toml 
$ ./ciscollector -r
```

## [Sample config file](https://github.com/klouddb/klouddbshield/blob/main/kshieldconfig_example.toml)

NOTE - In old version you will have label in config file as "[database]" instead of "[mysql]"
```
[mysql]
host="localhost"
port="3306"
# user="root"
# password="mysql111"
maxIdleConn = 2
maxOpenConn = 2

[postgres]
host="localhost" 
port="5432" 
user="postgres"
dbname="postgres"
password="postgres" 
maxIdleConn = 2
maxOpenConn = 2

[app]
debug = true

```
## Contributing 

We welcome PRs and Issue Reports

## Help 

Please reach us at support@klouddb.io 

