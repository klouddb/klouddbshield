package hbarules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klouddb/klouddbshield/model"
	"github.com/stretchr/testify/assert"
)

func Test_ScanHBAFile(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []model.HBAFIleRules
		err   error
	}{
		{
			name: "all database and user with localhost",
			files: map[string]string{
				"pg_hba.conf": `
# Allow any user on the local system to connect to any database with
# any database user name using Unix-domain sockets (the default for local
# connections).
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust

# The same using local loopback TCP/IP connections.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             127.0.0.1/32            trust

# The same as the previous line, but using a separate netmask column
#
# TYPE  DATABASE        USER            IP-ADDRESS      IP-MASK             METHOD
host    all             all             127.0.0.1       255.255.255.255     trust

# The same over IPv6.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             ::1/128                 trust

# The same using a host name (would typically cover both IPv4 and IPv6).
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             localhost               trust

# Allow any user from any host with IP address 192.168.93.x to connect
# to database "postgres" as the same user name that ident reports for
# the connection (typically the operating system user name).
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    postgres        all             192.168.93.0/24         ident

# Allow any user from host 192.168.12.10 to connect to database
# "postgres" if the user's password is correctly supplied.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    postgres        all             192.168.12.10/32        scram-sha-256

# Allow any user from hosts in the example.com domain to connect to
# any database if the user's password is correctly supplied.
#
# Require SCRAM authentication for most users, but make an exception
# for user 'mike', who uses an older client that doesn't support SCRAM
# authentication.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             mike            .example.com            md5
host    all             all             .example.com            scram-sha-256

# In the absence of preceding "host" lines, these three lines will
# reject all connections from 192.168.54.1 (since that entry will be
# matched first), but allow GSSAPI-encrypted connections from anywhere else
# on the Internet.  The zero mask causes no bits of the host IP address to
# be considered, so it matches any host.  Unencrypted GSSAPI connections
# (which "fall through" to the third line since "hostgssenc" only matches
# encrypted GSSAPI connections) are allowed, but only from 192.168.12.10.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             192.168.54.1/32         reject
hostgssenc all          all             0.0.0.0/0               gss
host    all             all             192.168.12.10/32        gss

# Allow users from 192.168.x.x hosts to connect to any database, if
# they pass the ident check.  If, for example, ident says the user is
# "bryanh" and he requests to connect as PostgreSQL user "guest1", the
# connection is allowed if there is an entry in pg_ident.conf for map
# "omicron" that says "bryanh" is allowed to connect as "guest1".
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             192.168.0.0/16          ident map=omicron

# If these are the only three lines for local connections, they will
# allow local users to connect only to their own databases (databases
# with the same name as their database user name) except for administrators
# and members of role "support", who can connect to all databases.  The file
# $PGDATA/admins contains a list of names of administrators.  Passwords
# are required in all cases.
#
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    sameuser        all                                     md5
host    all             @admins                                 md5
host    all             +support                                md5

# The last two lines above can be combined into a single line:
host    all             @admins,+support                        md5

# The database column can also use lists and file names:
host    db1,db2,@demodbs  all                                   md5
`,
				"admins": `testadmin
newadmin`,
				"demodbs": `newdbs
teestingdbs`,
			},
			want: []model.HBAFIleRules{
				{
					LineNumber: 12,
					Database:   "all",
					UserName:   "all",
					Address:    "127.0.0.1/32",
				},
				{
					LineNumber: 17,
					Database:   "all",
					UserName:   "all",
					Address:    "127.0.0.1",
					NetMask:    "255.255.255.255",
				},
				{
					LineNumber: 22,
					Database:   "all",
					UserName:   "all",
					Address:    "::1/128",
				},
				{
					LineNumber: 27,
					Database:   "all",
					UserName:   "all",
					Address:    "localhost",
				},
				{
					LineNumber: 34,
					Database:   "postgres",
					UserName:   "all",
					Address:    "192.168.93.0/24",
				},
				{
					LineNumber: 40,
					Database:   "postgres",
					UserName:   "all",
					Address:    "192.168.12.10/32",
				},
				{
					LineNumber: 50,
					Database:   "all",
					UserName:   "mike",
					Address:    ".example.com",
				},
				{
					LineNumber: 51,
					Database:   "all",
					UserName:   "all",
					Address:    ".example.com",
				},
				{
					LineNumber: 62,
					Database:   "all",
					UserName:   "all",
					Address:    "192.168.54.1/32",
				},
				{
					LineNumber: 63,
					Database:   "all",
					UserName:   "all",
					Address:    "0.0.0.0/0",
				},
				{
					LineNumber: 64,
					Database:   "all",
					UserName:   "all",
					Address:    "192.168.12.10/32",
				},
				{
					LineNumber: 73,
					Database:   "all",
					UserName:   "all",
					Address:    "192.168.0.0/16",
				},
				{
					LineNumber: 83,
					Database:   "sameuser",
					UserName:   "all",
					Address:    "",
				},
				{
					LineNumber: 84,
					Database:   "all",
					UserName:   "testadmin,newadmin",
					Address:    "",
				},
				{
					LineNumber: 91,
					Database:   "db1,db2,newdbs,teestingdbs",
					UserName:   "all",
					Address:    "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// write filedata in temp file and path temp file location
			pgConfigNAme := ""

			tmpDir := os.TempDir()
			for name, data := range tt.files {
				tmpFile, err := os.Create(filepath.Join(tmpDir, name))
				assert.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				if strings.Contains(name, "pg_hba.conf") {
					pgConfigNAme = tmpFile.Name()
				}

				fmt.Println("createdFileName", tmpFile.Name())

				_, err = tmpFile.WriteString(data)
				if err != nil {
					t.Errorf("ScanHBAFile() error = %v, wantErr %v", err, tt.err)
					return
				}
				tmpFile.Close()
			}

			got, err := ScanHBAFile(context.Background(), nil, pgConfigNAme)
			switch {
			case err == nil && tt.err != nil:
				t.Errorf("Expected error: %v, Got: nil", tt.err)
				return
			case err != nil && tt.err == nil:
				t.Errorf("Unexpected error: %v", err)
				return
			case err != nil && tt.err != nil && err.Error() != tt.err.Error():
				t.Errorf("Unexpected error. Expected: %v, Got: %v", tt.err, err)
				return
			}

			assert.EqualValues(t, tt.want, got, "ScanHBAFile() = %v, want %v", got, tt.want)
		})
	}
}

func TestParseHBAFileRules(t *testing.T) {
	type validationData struct {
		Database string
		UserName string
		Address  string
	}
	type args struct {
		rules []model.HBAFIleRules
	}
	tests := []struct {
		name         string
		args         args
		wantErr      bool
		validateWith []validationData
		unusedLines  []int
	}{
		// TODO: Add test cases.
		{
			name: "basic testing",
			args: args{
				rules: []model.HBAFIleRules{
					{
						LineNumber: 7,
						Database:   "all",
						UserName:   "all",
						Address:    "",
					},
					{
						LineNumber: 12,
						Database:   "all",
						UserName:   "all",
						Address:    "127.0.0.1/32",
					},
					{
						LineNumber: 17,
						Database:   "all",
						UserName:   "all",
						Address:    "127.0.0.1",
						NetMask:    "255.255.255.255",
					},
					{
						LineNumber: 22,
						Database:   "all",
						UserName:   "all",
						Address:    "::1/128",
					},
					{
						LineNumber: 27,
						Database:   "all",
						UserName:   "all",
						Address:    "localhost",
					},
					{
						LineNumber: 34,
						Database:   "postgres",
						UserName:   "all",
						Address:    "192.168.93.0/24",
					},
					{
						LineNumber: 40,
						Database:   "postgres",
						UserName:   "all",
						Address:    "192.168.12.10/32",
					},
					{
						LineNumber: 50,
						Database:   "all",
						UserName:   "mike",
						Address:    ".example.com",
					},
					{
						LineNumber: 51,
						Database:   "all",
						UserName:   "all",
						Address:    ".example.com",
					},
					{
						LineNumber: 62,
						Database:   "all",
						UserName:   "all",
						Address:    "192.168.54.1/32",
					},
					{
						LineNumber: 63,
						Database:   "all",
						UserName:   "all",
						Address:    "0.0.0.0/0",
					},
					{
						LineNumber: 64,
						Database:   "all",
						UserName:   "all",
						Address:    "192.168.12.10/32",
					},
					{
						LineNumber: 73,
						Database:   "all",
						UserName:   "all",
						Address:    "192.168.0.0/16",
					},
					{
						LineNumber: 83,
						Database:   "sameuser",
						UserName:   "all",
						Address:    "",
					},
					{
						LineNumber: 84,
						Database:   "all",
						UserName:   "testadmin,newadmin",
						Address:    "",
					},
					{
						LineNumber: 85,
						Database:   "all",
						UserName:   "+support",
						Address:    "",
					},
					{
						LineNumber: 88,
						Database:   "all",
						UserName:   "testadmin,newadmin,+support",
						Address:    "",
					},
					{
						LineNumber: 91,
						Database:   "db1,db2,newdbs,teestingdbs",
						UserName:   "all",
						Address:    "",
					},
				},
			},
			wantErr: false,
			validateWith: []validationData{
				{
					Database: "postgres",
					UserName: "user1",
					Address:  "192.168.93.5",
				},
				{
					Database: "postgres",
					UserName: "adminuser",
					Address:  "192.168.12.10",
				},
				{
					Database: "postgres",
					UserName: "user1",
					Address:  "127.0.0.1",
				},
				{
					Database: "postgres",
					UserName: "mike",
					Address:  "api.example.com",
				},
				{
					Database: "dummy",
					UserName: "dammy",
					Address:  "api.example.com",
				},
				{
					Database: "dummy",
					UserName: "dammy",
					Address:  "192.168.54.1",
				},
				{
					Database: "dummy",
					UserName: "dammy",
					Address:  "198.168.54.1",
				},
				{
					Database: "dummy",
					UserName: "dammy",
					Address:  "192.168.12.10",
				},
			},
			unusedLines: []int{17, 22, 27, 64, 73},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHBAFileRules(tt.args.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHBAFileRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, v := range tt.validateWith {
				got.ValidateEntry(v.Database, v.UserName, v.Address)
			}

			assert.EqualValues(t, tt.unusedLines, got.GetUnusedLines(), "ParseHBAFileRules() = %v, want %v", got.GetUnusedLines(), tt.unusedLines)
		})
	}
}
