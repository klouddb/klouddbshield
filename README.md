# KloudDB_Shield

[![GitHub Release][release-img]][release]
[![Go Report Card][report-card-img]][report-card]
[![Go Reference](https://pkg.go.dev/badge/github.com/klouddb/klouddbshield.svg)](https://pkg.go.dev/github.com/klouddb/klouddbshield)
[![Go Build](https://github.com/klouddb/klouddbshield/actions/workflows/release.yml/badge.svg)](https://github.com/klouddb/klouddbshield/actions/workflows/release.yml)
[![Go Vuln Check](https://github.com/klouddb/klouddbshield/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/klouddb/klouddbshield/actions/workflows/govulncheck.yml)

[release-img]: https://img.shields.io/github/release/klouddb/klouddbshield.svg?logo=github
[release]: https://github.com/klouddb/klouddbshield/releases
[report-card-img]: https://goreportcard.com/badge/github.com/klouddb/klouddbshield
[report-card]: https://goreportcard.com/report/github.com/klouddb/klouddbshield


## How to run this tool on my server ?

Logparser

```
ciscollector --logparser inactive_users --file-path /var/lib/postgresql/14/main/log/postgresql-2024-03-11_120824.log --prefix pid=%p,user=%u,db=%d,app=%a,client=%h



ciscollector --logparser unique_ip --file-path /var/lib/postgresql/14/main/log/postgresql-2024-03-11_120824.log --prefix pid=%p,user=%u,db=%d,app=%a,client=%h

NOTE : If you have multiple log files you can give wildcard in single quotes e.g '/var/lib/postgresql/14/main/log/postgresql-2024-03-11*;
```

Postgres  -   Please read https://klouddb.io/cis-benchmarks-for-postgres-klouddbshield-1-1/

HBA Scanner - Please read https://klouddb.io/hba-checker-klouddb-shield-1-4/

MySQL     -   Please read https://klouddb.io/releasing-first-version-of-klouddb-shield-mysql-cis-benchmarks/ 

RDS       -   Please read https://klouddb.io/klouddb-shield-1-2-rds-cis-benchmarks/

Currently we check for 94 controls - 40 controls(Postgres) 46 controls(MySQL) and 8 controls(RDS) and we plan to add more checks soon. We tested this tool on CentOS and Ubuntu ( PG 14 and PG13)

NOTE -  For some linux commands you might need root/sudo access 

You can directly download the package from releases section of repo and install the package (for example - rpm for centos and deb package for Ubuntu etc..) . You also need to edit config file after installing the package(see above mentioned blog post for detailed walkthrough)


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
secreport.json file generated
```

## How to run locally(without installing a package) ?

Install and run locally the server

```bash
$ go build -o ./ciscollector ./cmd/ciscollector
# Edit kshieldconfig.toml at path /etc/klouddbshield/kshieldconfig.toml 
$ ./ciscollector -r
```
## RDS Checks

Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly. NOTE - You need to run this tool from bastion host or from some place where you have access to your RDS instances(It only needs basic aws rds describe priivs and sns read privs )
```
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
export AWS_REGION="XXXXXXXXX"
```

## [Sample config file](https://github.com/klouddb/klouddbshield/blob/main/kshieldconfig_example.toml)
Below is sample file - If you are checking for postgres comment out the mysql section or if you are only checking mysql part , comment out the postgres part. Location of the config file is /etc/klouddbshield

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

