package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

func main() {
	argsWithoutProg := os.Args[1:]
	ntds := argsWithoutProg[0]
	hash := argsWithoutProg[1]

	ntdsFile, err := os.Open(ntds)
	if err != nil {
		log.Fatal(err)
	}
	defer ntdsFile.Close()

	hashFile, err := os.Open(hash)
	if err != nil {
		log.Fatal(err)
	}
	defer hashFile.Close()

	scannerNTDS := bufio.NewScanner(ntdsFile)
	scannerHASH := bufio.NewScanner(hashFile)

	_ = scannerHASH
	_ = scannerNTDS

	fmt.Println("A")
}
