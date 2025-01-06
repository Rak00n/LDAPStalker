package main

import (
	"flag"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
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
			printable := true
			for _, tempVal := range values {
				for _, char := range tempVal {
					if (char > unicode.MaxASCII) || (!unicode.IsPrint(char)) {
						printable = false
						break
					}
				}

			}
			value := strings.Join(values, ";")
			if printable {
				fmt.Println("\t", attr.Name+":", value)
			} else {
				fmt.Println("\t", attr.Name+":", fmt.Sprintf("%x", value))
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
			values := entry.GetAttributeValues(attr.Name)
			printable := true
			for _, tempVal := range values {
				for _, char := range tempVal {
					if (char > unicode.MaxASCII) || (!unicode.IsPrint(char)) {
						printable = false
						break
					}
				}

			}
			value := strings.Join(values, ";")
			if printable {
				_, err = fi.WriteString("\t" + attr.Name + ": " + value + "\r\n")
			} else {
				newVal := fmt.Sprintf("%x", value)
				_, err = fi.WriteString("\t" + attr.Name + ": " + newVal + "\r\n")
			}
		}
	}
	fi.Close()
}
func stalkerMonitor(bind *ldap.Conn) {
	topLevelObjects := make(map[string]map[string]string)
	fmt.Println("Waiting for stable LDAP state...")
	for {
		stable := true
		sr, err := bind.Search(searchRequest)
		if err != nil {
			log.Fatal(err)
		}
		for _, entry := range sr.Entries {
			mapKey := entry.GetAttributeValue("distinguishedName")
			_, ok := topLevelObjects[mapKey]
			if !ok {
				topLevelObjects[mapKey] = make(map[string]string)
				stable = false
			} else {
				for _, attr := range entry.Attributes {
					values := entry.GetAttributeValues(attr.Name)
					value := strings.Join(values, ";")
					printable := true
					for _, tempVal := range values {
						for _, char := range tempVal {
							if (char > unicode.MaxASCII) || (!unicode.IsPrint(char)) {
								printable = false
								break
							}
						}

					}
					var newVal string
					if printable {
						newVal = value
					} else {
						newVal = fmt.Sprintf("%x", value)
					}
					_, nestedOK := topLevelObjects[mapKey][attr.Name]
					if !nestedOK {
						//fmt.Println("New Attribute found")
						topLevelObjects[mapKey][attr.Name] = newVal
						stable = false
					}
				}
			}
		}
		if stable {
			break
		}
	}
	currentTime := time.Now()
	timestamp := currentTime.Format("2006-01-02 15:04:05")
	fmt.Println(timestamp, "Reached stable state. Waiting for changes...")
	for {
		time.Sleep(330 * time.Millisecond)
		currentTime := time.Now()
		timestamp := currentTime.Format("2006-01-02 15:04:05")
		sr, err := bind.Search(searchRequest)
		if err != nil {
			log.Fatal(err)
		}
		var newKeys []string
		for _, entry := range sr.Entries {
			mapKey := entry.GetAttributeValue("distinguishedName")
			newKeys = append(newKeys, mapKey)
			_, ok := topLevelObjects[mapKey]
			if !ok {
				fmt.Println(timestamp, "New object found", mapKey)
				topLevelObjects[mapKey] = make(map[string]string)
			} else {
				var newAttributes []string
				for _, attr := range entry.Attributes {
					newAttributes = append(newAttributes, attr.Name)
					values := entry.GetAttributeValues(attr.Name)
					value := strings.Join(values, ";")
					printable := true
					for _, tempVal := range values {
						for _, char := range tempVal {
							if (char > unicode.MaxASCII) || (!unicode.IsPrint(char)) {
								printable = false
								break
							}
						}

					}
					var newVal string
					if printable {
						newVal = value
					} else {
						newVal = fmt.Sprintf("%x", value)
					}
					_, nestedOK := topLevelObjects[mapKey][attr.Name]
					if !nestedOK {
						fmt.Println(timestamp, mapKey, " -> attribute created:", attr.Name+":", newVal)
						topLevelObjects[mapKey][attr.Name] = newVal
					} else {
						if topLevelObjects[mapKey][attr.Name] != newVal {
							fmt.Println(timestamp, mapKey, " -> attribute changed:", attr.Name, ":", topLevelObjects[mapKey][attr.Name], "->", newVal)
							topLevelObjects[mapKey][attr.Name] = newVal
						}

					}
				}

				for oldAttribute := range topLevelObjects[mapKey] {
					oldAttibuteFound := false
					for _, newAttribute := range newAttributes {
						if oldAttribute == newAttribute {
							oldAttibuteFound = true
							break
						}
					}
					if oldAttibuteFound == false {
						fmt.Println(timestamp, mapKey, " -> attribute removed:", oldAttribute)
						delete(topLevelObjects[mapKey], oldAttribute)
					}
				}
			}
		}
		for oldUser := range topLevelObjects {
			userFound := false
			for _, newKey := range newKeys {
				if newKey == oldUser {
					userFound = true
					break
				}
			}
			if userFound == false {
				fmt.Println(timestamp, "Object removed", oldUser)
				delete(topLevelObjects, oldUser)
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
