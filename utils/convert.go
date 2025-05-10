
package utils

import (
	"potfucker/modules"
)

func ConvertToResult(cr modules.CheckResult) Result {
	return Result{
		Description: cr.Name,
		Details:     cr.Details, 
		Probability: float64(cr.Score),
	}
}