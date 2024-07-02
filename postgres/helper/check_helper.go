package helper

import (
	"context"
	"database/sql"

	"github.com/klouddb/klouddbshield/model"
	"github.com/klouddb/klouddbshield/pkg/utils"
)

type CheckFunc func(*sql.DB, context.Context) (*model.Result, error)

type CheckHelper interface {
	ExecuteCheck(*sql.DB, context.Context) (*model.Result, error)
	GetControl() string
}

type checkHelper struct {
	result    *model.Result
	checkFunc CheckFunc
}

func NewCheckHelper(result *model.Result, checkFunc CheckFunc) CheckHelper {
	return &checkHelper{
		result:    result,
		checkFunc: checkFunc,
	}
}

func (c *checkHelper) ExecuteCheck(db *sql.DB, ctx context.Context) (*model.Result, error) {
	return c.checkFunc(db, ctx)
}

func (c *checkHelper) GetControl() string {
	return c.result.Control
}

func FilterCheckHelpers(checkHelpers []CheckHelper, controlSet utils.Set[string]) []CheckHelper {
	var filteredCheckHelpers []CheckHelper
	for _, checkHelper := range checkHelpers {
		if controlSet.Contains(checkHelper.GetControl()) {
			filteredCheckHelpers = append(filteredCheckHelpers, checkHelper)
		}
	}
	return filteredCheckHelpers
}

func FilterResultMap(resultMap map[string]*model.Result, controlSet utils.Set[string]) map[string]*model.Result {
	filteredCheckHelperMap := make(map[string]*model.Result)
	for control, result := range resultMap {
		if controlSet.Contains(result.Control) {
			filteredCheckHelperMap[control] = result
		}
	}
	return filteredCheckHelperMap
}
