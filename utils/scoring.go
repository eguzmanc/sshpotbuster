
package utils

import (
	"fmt"
)

type Result struct {
	Description string
	Details     string  
	Probability float64
}

func CalculateOverallProbability(results []Result) float64 {
	if len(results) == 0 {
		return 0
	}
	totalProb := 0.0
	for _, result := range results {
		totalProb += result.Probability
	}
	return totalProb / float64(len(results))
}

func PrintReport(results []Result, overallProbability float64) {
	fmt.Println("Results")
	for _, result := range results {
		fmt.Printf("%s - %s | %.0f%% the probability that this honeypot\n", 
			result.Description, 
			result.Details, 
			result.Probability)
	}
	fmt.Println("-------------------------------------")
	fmt.Printf("Final Honeypot Probability: %.0f%%\n", overallProbability)
}