package parselog

import (
	"fmt"
	"testing"
	"time"
)

type validateOut struct {
	s   string
	err error
}

func Test_dynamicParser(t *testing.T) {

	type validate struct {
		user        validateOut
		host        validateOut
		database    validateOut
		loglevel    string
		description string
		time        time.Time
	}

	type lineValidation struct {
		line       string
		validation validate
	}
	tests := []struct {
		name        string
		prefix      string
		validations []lineValidation
	}{
		{
			name:   "basic valid case",
			prefix: "%t [%p]: [%l-1] [trx_id=%x] user=%u,db=%d %r",
			validations: []lineValidation{
				{
					line: "2023-08-23 06:52:53 UTC [128]: [2997-1] [trx_id=3668] user=user4,db=postgres 192.168.0.30(48198)LOG:  duration: 0.150 ms",
					validation: validate{
						user: validateOut{
							s: "user4",
						},
						host: validateOut{
							s: "192.168.0.30",
						},
						database: validateOut{
							s: "postgres",
						},
						loglevel:    "LOG",
						description: "duration: 0.150 ms",
						time:        time.Date(2023, 8, 23, 6, 52, 53, 0, time.UTC),
					},
				},
				{
					line: "2023-08-23 06:52:53 UTC [128]: [2998-1] [trx_id=3668] user=user4,db=postgres 192.168.0.30(48198)LOG:  statement: END;",
					validation: validate{
						user: validateOut{
							s: "user4",
						},
						host: validateOut{
							s: "192.168.0.30",
						},
						database: validateOut{
							s: "postgres",
						},
						loglevel:    "LOG",
						description: "statement: END;",
						time:        time.Date(2023, 8, 23, 6, 52, 53, 0, time.UTC),
					},
				},
				{
					line: "2023-08-23 06:52:53 UTC [128]: [2999-1] [trx_id=0] user=user4,db=postgres 192.168.0.30(48198)LOG:  duration: 2.247 ms",
					validation: validate{
						user: validateOut{
							s: "user4",
						},
						host: validateOut{
							s: "192.168.0.30",
						},
						database: validateOut{
							s: "postgres",
						},
						loglevel:    "LOG",
						description: "duration: 2.247 ms",
						time:        time.Date(2023, 8, 23, 6, 52, 53, 0, time.UTC),
					},
				},
				{
					line: "2023-08-23 06:52:53 UTC [129]: [1-1] [trx_id=0] user=[unknown],db=[unknown] 192.168.0.30(49584)LOG:  connection received: host=192.168.0.30 port=49584",
					validation: validate{
						user: validateOut{
							err: fmt.Errorf("invalid value for user"),
						},
						host: validateOut{
							s: "192.168.0.30",
						},
						database: validateOut{
							err: fmt.Errorf("invalid value for database"),
						},
						loglevel:    "LOG",
						description: "connection received: host=192.168.0.30 port=49584",
						time:        time.Date(2023, 8, 23, 6, 52, 53, 0, time.UTC),
					},
				},
				{
					line: `2023-08-23 06:52:53 UTC [129]: [2-1] [trx_id=0] user=user4,db=postgres 192.168.0.30(49584)LOG:  connection authenticated: identity="user4" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
					validation: validate{
						user: validateOut{
							s: "user4",
						},
						host: validateOut{
							s: "192.168.0.30",
						},
						database: validateOut{
							s: "postgres",
						},
						loglevel:    "LOG",
						description: `connection authenticated: identity="user4" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:100)`,
						time:        time.Date(2023, 8, 23, 6, 52, 53, 0, time.UTC),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := GetDynamicBaseParser(tt.prefix)

			for _, validation := range tt.validations {
				parsedData, err := parser.Parse(validation.line)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				validateData(t, parsedData.GetUser, validation.validation.user)
				validateData(t, parsedData.GetHost, validation.validation.host)
				validateData(t, parsedData.GetDatabase, validation.validation.database)

				parsedTime := parsedData.GetTime()
				if !parsedTime.Equal(validation.validation.time) {
					t.Errorf("Unexpected time. Expected: %v, Got: %v", validation.validation.time, t)
				}

				if parsedData.GetLogLevel() != validation.validation.loglevel {
					t.Errorf("Unexpected loglevel. Expected: %v, Got: %v", validation.validation.loglevel, parsedData.GetLogLevel())
				}

				if parsedData.GetDescription() != validation.validation.description {
					t.Errorf("Unexpected description. Expected: %v, Got: %v", validation.validation.description, parsedData.GetDescription())
				}
			}
		})
	}
}

func validateData(t *testing.T, f1 func() (string, error), v validateOut) {
	val, err := f1()
	validateError(t, v.err, err)
	if val != v.s {
		t.Errorf("Unexpected value. Expected: %v, Got: %v", v.s, val)
	}
}

func validateError(t *testing.T, er1, er2 error) {
	// Verify the expected user
	if er1 == nil && er2 != nil {
		t.Errorf("Unexpected error: %v", er2)
	}
	if er1 != nil && er2 == nil {
		t.Errorf("Unexpected error: %v", er1)
	}
	if er1 != nil && er2 != nil && er1.Error() != er2.Error() {
		t.Errorf("Unexpected error. Expected: %v, Got: %v", er1, er2)
	}

}
