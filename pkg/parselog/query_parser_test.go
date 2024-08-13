package parselog

import (
	"testing"

	"github.com/klouddb/klouddbshield/pkg/piiscanner"
)

type Test struct {
	queries        []string
	expectedErr    error
	expectedOutput map[piiscanner.PIILabel][]PIIResp
}

func QueryTesterHelper(t *testing.T, tests *[]Test) {
	for _, test := range *tests {

		helper := NewQueryParser(nil, nil)

		err := func() error {

			err := helper.Init()
			if err != nil {
				return err
			}

			for _, query := range test.queries {
				err := helper.processQuery(query)
				if err != nil {
					return err
				}
			}

			return nil
		}()

		if err != test.expectedErr {
			t.Errorf("expected error %v, got %v", test.expectedErr, err)
			return
		}

		output := helper.GetPII()
		if len(output) != len(test.expectedOutput) {
			t.Errorf("expected %v, got %v", test.expectedOutput, helper.GetPII())
			return
		}

		for k, v := range test.expectedOutput {
			if _, ok := output[k]; !ok {
				t.Errorf("expected %v, got %v", test.expectedOutput, helper.GetPII())
				return
			}

			if len(output[k]) != len(v) {
				t.Errorf("expected %v, got %v", test.expectedOutput, helper.GetPII())
				return
			}

			for i, vv := range v {
				if output[k][i] != vv {
					t.Errorf("expected %v, got %v", test.expectedOutput, helper.GetPII())
					return
				}
			}
		}

	}
}

func QueryPercentageTesterHelper(t *testing.T, tests *[]Test) {
	num_correct := 0
	total_values := 0
	for _, test := range *tests {

		for _, expectedOutputs := range test.expectedOutput {
			total_values += len(expectedOutputs)
		}

		helper := NewQueryParser(nil, nil)

		err := func() error {

			err := helper.Init()
			if err != nil {
				return err
			}

			for _, query := range test.queries {
				err := helper.processQuery(query)
				if err != nil {
					return err
				}
			}

			return nil
		}()

		if err != test.expectedErr {
			continue
		}

		output := helper.GetPII()

		for k, v := range test.expectedOutput {
			if _, ok := output[k]; !ok {
				continue
			}

			for i, vv := range v {
				if i < len(output[k]) {
					if output[k][i] != vv {
						continue
					} else {
						num_correct++
					}
				}
			}
		}

	}

	percentage := float32(num_correct) / float32(total_values) * 100
	if percentage == 100 {
		t.Logf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	} else {
		t.Errorf("Correctly identified %d out of %d labels, which is %f%%", num_correct, total_values, float32(num_correct)/float32(total_values)*100)
	}
}

func TestQueryParser_Feed(t *testing.T) {

	tests := []Test{
		{

			queries: []string{
				`SELECT *
			FROM new_table
			WHERE username in (
				SELECT username
				FROM pgbench_accounts
				WHERE bid = 1 AND username = 'pradip'
			);`,
				`SELECT avg(abalance)
			FROM pgbench_accounts
			WHERE username = 'pradip' and bid = 1;`,
			},
			expectedErr: nil,
			expectedOutput: map[piiscanner.PIILabel][]PIIResp{
				piiscanner.PIILabel_Name: {
					{
						Col: "username",
						Val: "pradip",
					},
					{
						Col: "username",
						Val: "pradip",
					},
				},
			},
		},
		{
			queries: []string{
				// 			`SELECT *
				// FROM pgbench_accounts
				// WHERE username = 'kevin'`,
				`SELECT *
		FROM pgbench_accounts
		WHERE username = 'kevin' AND username = 'kevin'`,
			},
			expectedErr: nil,
			expectedOutput: map[piiscanner.PIILabel][]PIIResp{
				piiscanner.PIILabel_Name: {
					{
						Col: "username",
						Val: "kevin",
					},
					{
						Col: "username",
						Val: "kevin",
					},
				},
			},
		},
		{
			queries: []string{
				`SELECT *
		FROM pgbench_accounts
		WHERE address = '123 Main Street'`,
			},
			expectedErr: nil,
			expectedOutput: map[piiscanner.PIILabel][]PIIResp{
				piiscanner.PIILabel_Address: {
					{
						Col: "address",
						Val: "123 Main Street",
					},
				},
			},
		},
	}

	QueryTesterHelper(t, &tests)
}

func TestName(t *testing.T) {

	tests := []Test{
		{

			queries: []string{
				`SELECT *
			FROM new_table
			WHERE username in (
				SELECT username
				FROM pgbench_accounts
				WHERE bid = 1 AND username = 'pradip'
			);`,
				`SELECT avg(abalance)
			FROM pgbench_accounts
			WHERE username = 'pradip' and bid = 1;`,
				`SELECT *
		FROM pgbench_accounts
		WHERE username = 'kevin' AND username = 'Kevin'`,
			},
			expectedErr: nil,
			expectedOutput: map[piiscanner.PIILabel][]PIIResp{
				piiscanner.PIILabel_Name: {
					{
						Col: "username",
						Val: "pradip",
					},
					{
						Col: "username",
						Val: "pradip",
					},
					{
						Col: "username",
						Val: "kevin",
					},
					{
						Col: "username",
						Val: "Kevin",
					},
				},
			},
		},
	}

	QueryTesterHelper(t, &tests)
}

func TestNamePercentage(t *testing.T) {

	tests := []Test{
		{

			queries: []string{
				`SELECT *
			FROM new_table
			WHERE username in (
				SELECT username
				FROM pgbench_accounts
				WHERE bid = 1 AND username = 'pradip'
			);`,
				`SELECT avg(abalance)
			FROM pgbench_accounts
			WHERE username = 'Pradip' and bid = 1;`,
				`SELECT *
		FROM pgbench_accounts
		WHERE firstname = 'kevin' AND fname = 'Kevin'`,
				`SELECT *
			FROM new_table
			WHERE username in (
				SELECT username
				FROM pgbench_accounts
				WHERE bid = 1 AND fullname = 'Kelly Carroll'
			);`,
				`SELECT avg(abalance)
			FROM pgbench_accounts
			WHERE name = 'Vincent Rau' and bid = 1;`,
				`SELECT *
		FROM pgbench_accounts
		WHERE person = 'Jerry Kreiger' AND user = 'Lara Klocko'`,
				`SELECT *
		FROM pgbench_accounts
		WHERE login = 'Mara Renner' AND username = 'Jon Schamberger'`,
				`SELECT *
		FROM pgbench_accounts
		WHERE username = 'Rogelio Fahey' AND username = 'Eugenio Adams'`,
				`SELECT *
		FROM pgbench_accounts
		WHERE username = 'Ms. Hassie Larkin' AND username = 'Stacy Rice'`,
			},
			expectedErr: nil,
			expectedOutput: map[piiscanner.PIILabel][]PIIResp{
				piiscanner.PIILabel_Name: {
					{
						Col: "username",
						Val: "pradip",
					},
					{
						Col: "username",
						Val: "Pradip",
					},
					{
						Col: "firstname",
						Val: "kevin",
					},
					{
						Col: "fname",
						Val: "Kevin",
					},
					{
						Col: "fullname",
						Val: "Kelly Carroll",
					},
					{
						Col: "name",
						Val: "Vincent Rau",
					},
					{
						Col: "person",
						Val: "Jerry Kreiger",
					},
					{
						Col: "user",
						Val: "Lara Klocko",
					},
					{
						Col: "login",
						Val: "Mara Renner",
					},
					{
						Col: "username",
						Val: "Jon Schamberger",
					},
					{
						Col: "username",
						Val: "Rogelio Fahey",
					},
					{
						Col: "username",
						Val: "Eugenio Adams",
					},
					{
						Col: "username",
						Val: "Ms. Hassie Larkin",
					},
					{
						Col: "username",
						Val: "Stacy Rice",
					},
				},
			},
		},
	}

	QueryPercentageTesterHelper(t, &tests)
}
