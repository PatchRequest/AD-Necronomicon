package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"os"
	"strings"
	"sync"
)

type result struct {
	Hash string
}

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

func checkOnlineHash(str string, backend string, ssl bool, key string, speed string) {
	defer wg.Done()
	username := strings.Split(str, "-.-")[0]
	hash := strings.Split(str, "-.-")[1]
	urlBackend := ""
	if ssl {
		urlBackend += "https://"
	} else {
		urlBackend += "http://"
	}
	urlBackend += backend
	hashPart := ""
	if speed == "slow" {
		hashPart = hash[:15]
	} else {
		hashPart = hash
	}

	//form := url.Values{}
	//form.Add("username", username)
	//form.Add("hash", hash)
	//form.Add("speed", speed)
	//form.Add("key", key)
	username = strings.ReplaceAll(username, "\\", "\\\\")
	jsonStr := []byte(`{"username":"` + username + `","hash":"` + hashPart + `","speed":"` + speed + `","key":"` + key + `"}`)
	//encodedForm := form.Encode()
	//fmt.Println(encodedForm)
	req, err := http.NewRequest("POST", urlBackend, bytes.NewBuffer(jsonStr))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if string(body) == "null" {
		return
	}

	var hashes []result
	json.Unmarshal(body, &hashes)

	for _, v := range hashes {
		if speed == "fast" {
			if v.Hash == hash {
				fmt.Println("[+] " + username + ":" + v.Hash)
			}
		} else {
			if strings.HasPrefix(v.Hash, hash) {

				fmt.Println("[+] " + username + ":" + v.Hash)
			}
		}
	}

	//fmt.Println(jsonObj)

	//fmt.Println("response Body:", string(body))
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
	var foundHashes []string
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
		backend := argsWithoutProg[3]
		ssl := argsWithoutProg[4]
		key := argsWithoutProg[5]
		speed := argsWithoutProg[6]

		fmt.Println("[*] Reading NTDS Dump")
		scannerNTDS := bufio.NewScanner(ntdsFile)
		for scannerNTDS.Scan() {
			foundHashes = append(foundHashes, scannerNTDS.Text())
		}
		fmt.Println("[*] Starting Comparison \n")
		sslBool := ssl == "True"

		for _, hash := range foundHashes {

			go checkOnlineHash(hash, backend, sslBool, key, speed)
			wg.Add(1)
		}
		wg.Wait()
		fmt.Println("\n[*] Starting CleanUp")
		ntdsFile.Close()
		e := os.Remove(ntds)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println("[+] CleanUp finished!")
	}

}
