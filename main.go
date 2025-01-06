package main

import (
	"flag"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
	"os"
	"strconv"
	"unicode"
)

var dcIP string
var dcPort int
var domainName string
var adminUsername string
var adminPassword string
var action string

func init() {
	flag.StringVar(&action, "action", "print", "Action to execute. \"print\" - prints all the data to stdout; \"dump\" - save all LDAP data into file ldap.dump; \"monitor\" - start monitoring changes of LDAP")
	flag.StringVar(&dcIP, "dcip", "127.0.0.1", "LDAP server IP address")
	flag.IntVar(&dcPort, "dcPort", 389, "LDAP server port")
	flag.StringVar(&domainName, "domain", "test", "Your domain name (ex: test.local)")
	flag.StringVar(&adminUsername, "user", "administrator", "Domain administrator username")
	flag.StringVar(&adminPassword, "password", "password", "Domain administrator password")
	flag.Parse()
}

func stalkerPrint(entries []*ldap.Entry) {
	for _, entry := range entries {
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
				fmt.Println("\t", attr.Name+":", entry.GetAttributeValue(attr.Name))
			} else {
				fmt.Println("\t", attr.Name+":", fmt.Sprintf("%x", entry.GetRawAttributeValue(attr.Name)))
			}

		}
	}
}
func stalkerDump(entries []*ldap.Entry) {
	fi, err := os.Create("ldap.dump")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		_, err = fi.WriteString(entry.DN + "\r\n")
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
				_, err = fi.WriteString("\t" + attr.Name + ": " + entry.GetAttributeValue(attr.Name) + "\r\n")
			} else {
				_, err = fi.WriteString("\t" + attr.Name + ": " + fmt.Sprintf("%x", entry.GetRawAttributeValue(attr.Name)) + "\r\n")
			}
		}
	}
	fi.Close()
}
func main() {
	bindusername := domainName + "\\" + adminUsername
	bindpassword := adminPassword
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

	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}

	searchRequest := ldap.NewSearchRequest(
		"dc=test,dc=local",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn=*)",
		[]string{},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if action == "print" {
		stalkerPrint(sr.Entries)
	}
	if action == "dump" {
		stalkerDump(sr.Entries)
	}
	if action == "monitor" {
		stalkerMonitor(sr.Entries)
	}
}
