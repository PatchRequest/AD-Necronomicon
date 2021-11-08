package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

func checkHash(list []string, str string) {
	defer wg.Done()

	for _, v := range list {
		hash := strings.Split(v, "-.-")[1]

		if hash == str[:32] {

			nicePrint := strings.ReplaceAll(v, "-.-", "    ")
			fmt.Println("[+] " + nicePrint)

			return
		}
	}
	return
}

var wg sync.WaitGroup

func main() {
	argsWithoutProg := os.Args[1:]
	ntds := argsWithoutProg[0]
	hash := argsWithoutProg[1]
	mode := argsWithoutProg[2]

	ntdsFile, err := os.Open(ntds)
	if err != nil {
		log.Fatal(err)
	}
	defer ntdsFile.Close()
	if mode == "offline" {
		// Offline Mode
		hashFile, err := os.Open(hash)
		if err != nil {
			log.Fatal(err)
		}
		defer hashFile.Close()
		fmt.Println("[*] Reading NTDS Dump")
		scannerNTDS := bufio.NewScanner(ntdsFile)
		fmt.Println("[*] Reading Hash Library")
		scannerHASH := bufio.NewScanner(hashFile)

		var foundHashes []string

		for scannerNTDS.Scan() {
			foundHashes = append(foundHashes, scannerNTDS.Text())
		}
		fmt.Println("[*] Starting Comparison \n")
		for scannerHASH.Scan() {
			copy := scannerHASH.Text()

			go checkHash(foundHashes, copy)
			wg.Add(1)
		}
		wg.Wait()
		fmt.Println("\n[*] Starting CleanUp")
		ntdsFile.Close()
		hashFile.Close()
		e := os.Remove(ntds)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println("[+] CleanUp finished!")

	} else {

	}

}
