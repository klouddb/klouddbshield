package logparser

import (
	"context"

	"github.com/klouddb/klouddbshield/pkg/config"
	"github.com/klouddb/klouddbshield/pkg/parselog"
)

type PasswordLeakHelper struct {
	*parselog.PasswordLeakParser
}

func NewPasswordLeakHelper() *PasswordLeakHelper {
	return &PasswordLeakHelper{}
}

func (i *PasswordLeakHelper) Init(ctx context.Context, cnf *config.Config, baseParser parselog.BaseParser) error {

	i.PasswordLeakParser = parselog.NewPasswordLeakParser(cnf, baseParser)
	return nil
}

func (i *PasswordLeakHelper) GetResult(ctx context.Context) []parselog.LeakedPasswordResponse {
	return i.PasswordLeakParser.GetLeakedPasswords()
}
