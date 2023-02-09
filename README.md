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

!! Please read our detailed blog post https://klouddb.io/releasing-first-version-of-klouddb-shield-mysql-cis-benchmarks/ before using this tool !!

NOTE - For some linux commands you might need root/sudo access 

You can directly download the package from [releases](https://github.com/klouddb/klouddbshield/releases) section of repo and install the package (for example - rpm for centos and deb package for Ubuntu etc..) . You also need to edit config file after installing the package(see above mentioned blog post for detailed walkthrough)


```bash
# centos based OS
$ rpm -i <ciscollector file>.rpm

# debian based OS
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
# Edit cisconfig.toml at path /etc/mysqlcollector/cisconfig.toml 
$ ./ciscollector -r
```

## Contributing 

We welcome PRs and Issue Reports

## Help 

Please reach us at support@klouddb.io

