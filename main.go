package main

import (
	"flag"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode"
)

var dcIP string
var dcPort int
var domainName string
var adminUsername string
var adminPassword string
var action string
var searchRequest *ldap.SearchRequest

func init() {
	flag.StringVar(&action, "action", "print", "Action to execute. \"print\" - prints all the data to stdout; \"dump\" - save all LDAP data into file ldap.dump; \"monitor\" - start monitoring changes of LDAP")
	flag.StringVar(&dcIP, "dcip", "127.0.0.1", "LDAP server IP address")
	flag.IntVar(&dcPort, "dcPort", 389, "LDAP server port")
	flag.StringVar(&domainName, "domain", "test", "Your domain name (ex: test.local)")
	flag.StringVar(&adminUsername, "user", "administrator", "Domain administrator username")
	flag.StringVar(&adminPassword, "password", "password", "Domain administrator password")
	flag.Parse()
}

func stalkerPrint(bind *ldap.Conn) {

	sr, err := bind.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range sr.Entries {
		fmt.Println(entry.DN)
		for _, attr := range entry.Attributes {
			values := entry.GetAttributeValues(attr.Name)
			value := strings.Join(values, ";")
			printable := true
			for _, char := range value {
				if char > unicode.MaxASCII {
					printable = false
					break
				}
			}
			if printable {
				fmt.Println("\t", attr.Name+":", entry.GetAttributeValues(attr.Name))
			} else {
				fmt.Println("\t", attr.Name+":", fmt.Sprintf("%x", entry.GetRawAttributeValues(attr.Name)))
			}

		}
	}
}
func stalkerDump(bind *ldap.Conn) {
	fi, err := os.Create("ldap.dump")
	if err != nil {
		panic(err)
	}
	sr, err := bind.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range sr.Entries {
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
func stalkerMonitor(bind *ldap.Conn) {
	topLevelObjects := make(map[string][]byte)
	fmt.Println("Waiting for stable LDAP state...")
	sr, err := bind.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range sr.Entries {
		mapKey := entry.GetAttributeValue("distinguishedName")
		fmt.Println(mapKey)
		_, ok := topLevelObjects[mapKey]
		if !ok {
			topLevelObjects[mapKey] = []byte{11, 12}
		}
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
func main() {
	domainNameSlice := strings.Split(domainName, ".")
	userDomain := domainNameSlice[0]
	baseDNSlice := []string{}
	for _, domain := range domainNameSlice {
		baseDNSlice = append(baseDNSlice, "dc="+domain)
	}
	baseDN := strings.Join(baseDNSlice, ",")
	bindusername := userDomain + "\\" + adminUsername
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

	searchRequest = ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn=*)",
		[]string{},
		nil,
	)

	if action == "print" {
		stalkerPrint(l)
	}
	if action == "dump" {
		stalkerDump(l)
	}
	if action == "monitor" {
		stalkerMonitor(l)
	}
}
