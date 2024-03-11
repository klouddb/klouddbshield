package parselog

import (
	"sort"
	"testing"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestUniqueIPParser_Feed(t *testing.T) {
	tests := []struct {
		name        string
		cnf         *config.Config
		lines       []string
		expectedIPs []string
		err         error
	}{
		{
			name: "basic valid case",
			cnf: &config.Config{
				LogParser: &config.LogParser{
					PgSettings: &model.PgSettings{
						LogLinePrefix: "%t [%p]: [%l-1] [trx_id=%x] user=%u,db=%d %r",
					},
				},
			},

			lines: []string{
				`2023-08-23 06:52:03 UTC [1]: [7-1] [trx_id=0] user=,db= LOG:  database system is ready to accept connections`,
				`2023-08-23 06:52:10 UTC [82]: [1-1] [trx_id=0] user=[unknown],db=[unknown] 192.168.0.25(50680)LOG:  connection received: host=192.168.0.25 port=50680`,
				`2023-08-23 06:52:10 UTC [82]: [2-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  connection authenticated: identity="myuser" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
				`2023-08-23 06:52:10 UTC [82]: [3-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  connection authorized: user=myuser database=postgres application_name=psql`,
				`2023-08-23 06:52:10 UTC [82]: [4-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  statement: CREATE USER user0 WITH PASSWORD 'password';`,
				`2023-08-23 06:52:10 UTC [82]: [5-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  duration: 11.448 ms`,
				`2023-08-23 06:52:10 UTC [83]: [1-1] [trx_id=0] user=[unknown],db=[unknown] 192.168.0.25(50684)LOG:  connection received: host=192.168.0.25 port=50684`,
				`2023-08-23 06:52:10 UTC [83]: [2-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  connection authenticated: identity="myuser" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
				`2023-08-23 06:52:10 UTC [83]: [3-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  connection authorized: user=myuser database=postgres application_name=psql`,
				`2023-08-23 06:52:10 UTC [83]: [4-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  statement: CREATE USER user1 WITH PASSWORD 'password';`,
				`2023-08-23 06:52:10 UTC [83]: [5-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  duration: 11.899 ms`,
			},
			expectedIPs: []string{"192.168.0.25"},
			err:         nil,
		},
		{
			name: "with connection log",
			cnf: &config.Config{
				LogParser: &config.LogParser{
					PgSettings: &model.PgSettings{
						LogLinePrefix:  "%t [%p]: [%l-1] [trx_id=%x] user=%u,db=%d ",
						LogConnections: true,
					},
				},
			},

			lines: []string{
				`2023-08-23 06:52:10 UTC [85]: [1-1] [trx_id=0] user=[unknown],db=[unknown] LOG:  connection received: host=192.168.0.25 port=50710`,
			},
			expectedIPs: []string{"192.168.0.25"},
			err:         nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseParser := GetDynamicBaseParser(tt.cnf.LogParser.PgSettings.LogLinePrefix)
			u := NewUniqueIPParser(tt.cnf, baseParser)

			for _, line := range tt.lines {
				err := u.Feed(line)
				if err == nil && tt.err != nil {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
				if err != nil && tt.err == nil {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
				if err != nil && tt.err != nil && err.Error() != tt.err.Error() {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
			}

			var ips []string
			for ip := range u.GetUniqueIPs() {
				ips = append(ips, ip)
			}

			sort.Strings(ips)

			assert.Equal(t, tt.expectedIPs, ips)
		})
	}
}

func TestUniqueUsers_Feed(t *testing.T) {
	tests := []struct {
		name          string
		cnf           *config.Config
		lines         []string
		expectedUsers []string
		err           error
	}{
		{
			name: "basic valid case",
			cnf: &config.Config{
				LogParser: &config.LogParser{
					PgSettings: &model.PgSettings{
						LogLinePrefix: "%t [%p]: [%l-1] [trx_id=%x] user=%u,db=%d %r",
					},
				},
			},

			lines: []string{
				`2023-08-23 06:52:03 UTC [1]: [7-1] [trx_id=0] user=,db= LOG:  database system is ready to accept connections`,
				`2023-08-23 06:52:10 UTC [82]: [1-1] [trx_id=0] user=[unknown],db=[unknown] 192.168.0.25(50680)LOG:  connection received: host=192.168.0.25 port=50680`,
				`2023-08-23 06:52:10 UTC [82]: [2-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  connection authenticated: identity="myuser" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
				`2023-08-23 06:52:10 UTC [82]: [3-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  connection authorized: user=myuser database=postgres application_name=psql`,
				`2023-08-23 06:52:10 UTC [82]: [4-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  statement: CREATE USER user0 WITH PASSWORD 'password';`,
				`2023-08-23 06:52:10 UTC [82]: [5-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50680)LOG:  duration: 11.448 ms`,
				`2023-08-23 06:52:10 UTC [83]: [1-1] [trx_id=0] user=[unknown],db=[unknown] 192.168.0.25(50684)LOG:  connection received: host=192.168.0.25 port=50684`,
				`2023-08-23 06:52:10 UTC [83]: [2-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  connection authenticated: identity="myuser" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
				`2023-08-23 06:52:10 UTC [83]: [3-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  connection authorized: user=myuser database=postgres application_name=psql`,
				`2023-08-23 06:52:10 UTC [83]: [4-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  statement: CREATE USER user1 WITH PASSWORD 'password';`,
				`2023-08-23 06:52:10 UTC [83]: [5-1] [trx_id=0] user=myuser,db=postgres 192.168.0.25(50684)LOG:  duration: 11.899 ms`,
			},
			expectedUsers: []string{"myuser"},
			err:           nil,
		},
		{
			name: "with connection log",
			cnf: &config.Config{
				LogParser: &config.LogParser{
					PgSettings: &model.PgSettings{
						LogLinePrefix:  "%t [%p]: [%l-1] [trx_id=%x] db=%d ",
						LogConnections: true,
					},
				},
			},

			lines: []string{
				`2023-08-23 06:52:10 UTC [89]: [3-1] [trx_id=0] db=postgres LOG:  connection authorized: user=myuser database=postgres application_name=psql`,
			},
			expectedUsers: []string{"myuser"},
			err:           nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseParser := GetDynamicBaseParser(tt.cnf.LogParser.PgSettings.LogLinePrefix)
			u := NewUserParser(tt.cnf, baseParser)

			for _, line := range tt.lines {
				err := u.Feed(line)
				if err == nil && tt.err != nil {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
				if err != nil && tt.err == nil {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
				if err != nil && tt.err != nil && err.Error() != tt.err.Error() {
					t.Errorf("UniqueIPParser.Feed() error = %v, wantErr %v", err, tt.err)
					return
				}
			}

			var users []string
			for user := range u.GetUniqueUser() {
				users = append(users, user)
			}

			sort.Strings(users)

			assert.Equal(t, tt.expectedUsers, users)
		})
	}
}
