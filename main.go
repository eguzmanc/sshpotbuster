package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"potfucker/modules"
	"potfucker/utils"
)

func main() {
	busted := `
               __ ___.                   __                
______   _____/  |\_ |__  __ __  _______/  |_  ___________ 
\____ \ /  _ \   __\ __ \|  |  \/  ___/\   __\/ __ \_  __ \
|  |_> >  <_> )  | | \_\ \  |  /\___ \  |  | \  ___/|  | \/
|   __/ \____/|__| |___  /____//____  > |__|  \___  >__|   
|__|                   \/           \/            \/       
	`
	fmt.Println(busted)
	targetIP := getValidatedIP()
	if targetIP == "" {
		return
	}
	if !checkServerAvailability(targetIP) {
		return
	}
	checkResults := modules.RunChecks(targetIP)
	var finalResults []utils.Result
	for _, res := range checkResults {
		finalResults = append(finalResults, utils.ConvertToResult(res))
	}
	overallProbability := utils.CalculateOverallProbability(finalResults)
	utils.PrintReport(finalResults, overallProbability)
}

func getValidatedIP() string {
	fmt.Print("\nServer IP [host:port]: ")
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Println("error reading out:", err)
		return ""
	}

	input = strings.TrimSpace(input)
	if input == "" {
		fmt.Println("IP cant be blank")
		return ""
	}

	if !strings.Contains(input, ":") {
		input += ":22"
	}

	host, port, err := net.SplitHostPort(input)
	if err != nil {
		fmt.Println("Invalid adress format. Use: [host:port]")
		return ""
	}

	if ip := net.ParseIP(host); ip == nil {
		if _, err := net.LookupHost(host); err != nil {
			fmt.Printf("cannot resolve adress %s: %v\n", host, err)
			return ""
		}
	}

	if _, err := net.LookupPort("tcp", port); err != nil {
		fmt.Printf("invalid port %s: %v\n", port, err)
		return ""
	}

	return input
}

func checkServerAvailability(addr string) bool {
	fmt.Printf("\nChecking accesibly %s...\n", addr)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Printf("Server not accessable: %v\n", err)
		return false
	}
	defer conn.Close()

	fmt.Println("Server validated , started check...\n")
	return true
}