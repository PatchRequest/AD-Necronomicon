package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

var knowHashes []string
var wg sync.WaitGroup

func main() {

	ntdsFile, err := os.Open("dumb.ntds")
	if err != nil {
		log.Fatal(err)
	}
	defer ntdsFile.Close()

	hashFile, err := os.Open("hashlist.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer hashFile.Close()

	fmt.Println("[*] Reading NTDS Dump")
	scannerNTDS := bufio.NewScanner(ntdsFile)
	fmt.Println("[*] Reading Hash Library")
	scannerHASH := bufio.NewScanner(hashFile)

	for scannerHASH.Scan() {
		knowHashes = append(knowHashes, scannerHASH.Text())
	}

	for scannerNTDS.Scan() {
		foundRawData := scannerNTDS.Text()
		foundHash := splitData(foundRawData)

		go checkHash(foundHash)
		wg.Add(1)
	}
	wg.Wait()

	fmt.Println("[*] Cleaning up")
	os.Remove("dumb.ntds")
}
func checkHash(foundHash []string) {
	defer wg.Done()
	for _, v := range knowHashes {
		if v == foundHash[1] {
			fmt.Println("[*] Found User: " + foundHash[0] + "\n Hash: " + foundHash[1])
		}
	}
}
func splitData(raw string) []string {
	// EXAMPLE: Administrator:500:aad3b435b51404eeaad3b435b51404ee:5b4c6335673a75f13ed948e848f00840::: (pwdLastSet=2022-02-12 17:21) (status=Enabled)
	// Extract username
	username := strings.Split(raw, ":")[0]
	// Extract hash
	hash := strings.Split(raw, ":")[3]

	return []string{username, hash}
}
