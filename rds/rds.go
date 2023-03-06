package rds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"log"

	"github.com/klouddb/klouddbshield/model"
	cons "github.com/klouddb/klouddbshield/pkg/const"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

// # Set required ENV variables
// $ export AWS_ACCESS_KEY_ID=key-id
// $ export AWS_SECRET_ACCESS_KEY=access-key
// $ export AWS_SESSION_TOKEN=session_token
// $ export AWS_REGION=us-west-1

type Command interface {
	Run() error
}

type RdsCommand struct {
}

func ExecRdsCommand(ctx context.Context, cmd string) (result *model.Result, cmdOutPut CmdOutput, err error) {
	result = &model.Result{}
	rdsCmd, err := NewRdsCommand()
	if err != nil {
		log.Println("error creating rds command", err)
		result.Status = "Fail"
		result.FailReason = fmt.Errorf("error creating command %s", err)
		return result, cmdOutPut, err
	}
	return rdsCmd.Run(ctx, cmd)
}

func NewRdsCommand() (rdsCommand *RdsCommand, err error) {
	rdsCommand = &RdsCommand{}
	defer func() {

		commonTroubleSuggestion := "\n error retrieving databases through  aws command line\nUnable to run AWS cli commands - Please check if you have configured cli properly to check the status of your RDS instances - NOTE : You need to run this separately for each region \n1. check if aws cli is installed \n2. check if aws configure is properly set  \n3. check if AWS_ACCESS_KEY_ID , AWS_SECRET_ACCESS_KEY , AWS_REGION are exposed \n No more further checks would be run."

		var cmdOutput CmdOutput
		_, cmdOutput, err = rdsCommand.Run(context.Background(), "aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'")
		if err != nil {
			log.Fatalln("error retrieving rds instances"+commonTroubleSuggestion, err)
		}
		var arrayOfDataBases []string
		err = json.Unmarshal([]byte(cmdOutput.StdOut), &arrayOfDataBases)
		if err != nil {

			fmt.Println("Unmarshalling issue happened"+commonTroubleSuggestion, cmdOutput.StdOut, cmdOutput.StdErr, err)
			os.Exit(1)
		}
		if len(arrayOfDataBases) == 0 {
			err = errors.New("no rds databases exist")
			log.Fatalln("no rds databases exists"+commonTroubleSuggestion, err)
		}

	}()

	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		err = fmt.Errorf("AWS_ACCESS_KEY_ID  is missing")
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		err = fmt.Errorf("AWS_SECRET_ACCESS_KEY  is missing")
	}
	// for now this condition is not mandatory
	// if os.Getenv("AWS_SESSION_TOKEN") == "" {
	// 	return nil, fmt.Errorf("AWS_SESSION_TOKEN  is missing")

	// }
	if os.Getenv("AWS_REGION") == "" {
		err = fmt.Errorf("AWS_REGION  is missing")
	}
	return
}

type CmdOutput struct {
	StdOut string
	StdErr string
	Err    error
}

// Run a linux command sent
func (r *RdsCommand) Run(ctx context.Context, cmd string) (result *model.Result, cmdOutPut CmdOutput, err error) {
	result = &model.Result{}

	// log.Println("\nrunning command ", cmd)
	cmdOutPut.StdOut, cmdOutPut.StdErr, cmdOutPut.Err = utils.ExecBash(cmd)
	if cmdOutPut.StdOut == "" && cmdOutPut.StdErr == "" && strings.Contains(err.Error(), "exit status 1") {
		result.Status = "Fail"
		result.FailReason = fmt.Sprintf(cons.CMDReturnNothingFmt, cmd)
		return result, cmdOutPut, nil
	}
	if err != nil || cmdOutPut.StdErr != "" {
		result.Status = "Fail"
		if err != nil {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, err.Error(), cmdOutPut.StdErr)
		} else {
			result.FailReason = fmt.Sprintf(cons.ErrFmt, cmd, "", cmdOutPut.StdErr)
		}

		return result, cmdOutPut, err
	}

	if cmdOutPut.StdOut == "" {
		result.Status = "Fail"
	} else {
		result.Status = "Pass"
	}
	return result, cmdOutPut, nil
}
