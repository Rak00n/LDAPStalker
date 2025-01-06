package main

import (
	"flag"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
	"strconv"
	"unicode"
)

var dcIP string
var dcPort int
var domainName string
var adminUsername string
var adminPassword string

func init() {
	flag.StringVar(&dcIP, "dcip", "127.0.0.1", "LDAP server IP address")
	flag.IntVar(&dcPort, "dcPort", 389, "LDAP server port")

}

func main() {
	bindusername := "test\\administrator"
	bindpassword := "sxdzSXDZ!@#123"

	l, err := ldap.DialURL("ldap://" + dcIP + ":" + strconv.Itoa(dcPort))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Reconnect with TLS
	//err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	//if err != nil {
	//	log.Fatal(err)
	//}

	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		"dc=test,dc=local",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn=*)",
		//[]string{"dn", "objectGUID"},
		[]string{},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	//if len(sr.Entries) != 1 {
	//	fmt.Println(sr)
	//	fmt.Println(sr.Entries)
	//	//log.Fatal("User does not exist or too many entries returned")
	//}
	for _, entry := range sr.Entries {
		fmt.Println(entry.DN)
		for _, attr := range entry.Attributes {
			value := entry.GetAttributeValue(attr.Name)
			printable := true
			for _, char := range value {
				if char > unicode.MaxASCII {
					printable = false
					break
				}
			}
			if printable {
				fmt.Println("\t", attr.Name, entry.GetAttributeValue(attr.Name))
			} else {
				fmt.Println("\t", attr.Name, fmt.Sprintf("%x", entry.GetRawAttributeValue(attr.Name)))
			}

		}
	}
	userdn := sr.Entries[0].DN
	fmt.Println(userdn)

}
