/*
Monitor /etc/passwd and /etc/shadow for changes and send diff to email
*/

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"os"
	"time"

	"gopkg.in/fsnotify.v1" // go get gopkg.in/fsnotify.v1
)

func randombytes(n int) []byte {
	// generate n random bytes
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

type usrwtch struct {
	// email of admin
	adminEmail string
	// smtp server
	smtpServer string
	// internal hash string (SHA512 - 64 bytes)
	hashString [64]byte
	// signature of /etc/passwd
	passwdSig [64]byte
	// signature of /etc/shadow
	//shadowSig [64]byte
	// keep passwd in byte
	passwdBuf []byte
	// usernames array
	usernames []string
}

func (usrwtchmain *usrwtch) gethash(fname string) [64]byte {
	var hash [64]byte
	// get hash of file
	f, err := os.Open(fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	h := sha512.New()
	_, err = io.Copy(h, f)
	if err != nil {
		panic(err)
	}
	copy(hash[:], h.Sum(nil))
	return hash
}

func getUsernames(buf []byte) []string {
	// get usernames from passwd file
	// split by \n and :
	// return array of usernames
	var usernames []string

	// split by \n
	lines := bytes.Split(buf, []byte("\n"))
	for _, line := range lines {
		// split by :
		fields := bytes.Split(line, []byte(":"))
		if len(fields) > 0 {
			usernames = append(usernames, string(fields[0]))
		}
	}
	return usernames
}

func (usrwtchmain *usrwtch) readPasswd() {
	// read /etc/passwd and /etc/shadow, calculate hash and store in struct
	usrwtchmain.passwdSig = usrwtchmain.gethash("/etc/passwd")
	//usrwtchmain.shadowSig = usrwtchmain.gethash("/etc/shadow")
	// read also old passwd in passwdBuf for diffs
	f, err := os.Open("/etc/passwd")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	usrwtchmain.passwdBuf, err = io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	usrwtchmain.usernames = getUsernames(usrwtchmain.passwdBuf)
}

func (usrwtchmain *usrwtch) sendEmail(data string) {
	// send email with diff
	subject := "usrwtchchange"
	msg := "From: usrwtchchange\nSubject: " + subject + "\n\n" + data
	// connect to server by tcp
	netconn, err := net.Dial("tcp", usrwtchmain.smtpServer)
	if err != nil {
		log.Fatal(err)
	}
	// send email
	c, err := smtp.NewClient(netconn, usrwtchmain.smtpServer)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	// TODO(nuclearcat): add proper hostname retrieval
	c.Hello("nuclearcat.com")

	c.Mail(usrwtchmain.adminEmail)
	c.Rcpt(usrwtchmain.adminEmail)
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	defer wc.Close()
	_, err = wc.Write([]byte(msg))
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Email sent:")
	// printout content
	log.Println(msg)
}

func cmpUsernames(usernames1 []string, usernames2 []string) string {
	var retbuf string = ""
	// compare two arrays of usernames and return diff
	for _, username1 := range usernames1 {
		found := false
		for _, username2 := range usernames2 {
			if username1 == username2 {
				found = true
				break
			}
		}
		if !found {
			retbuf += "Username removed: " + username1 + "\n"
		}
	}
	for _, username2 := range usernames2 {
		found := false
		for _, username1 := range usernames1 {
			if username1 == username2 {
				found = true
				break
			}
		}
		if !found {
			retbuf += "Username added: " + username2 + "\n"
		}
	}
	return retbuf
}

// Generate string for current timezone datetime like 01.01.2017 12:00:00
func getDateTime() string {
	t := time.Now()
	zone, _ := t.Zone()
	dateTime := fmt.Sprintf("%02d.%02d.%04d %02d:%02d:%02d %s", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute(), t.Second(), zone)
	return dateTime
}

func main() {
	var usrwtchmain usrwtch
	if len(os.Args) < 3 {
		panic("Usage: usrwtchchange <admin email> <smtp server>")
	}

	// admin email is first argument (TODO(nuclearcat): add named arguments)
	usrwtchmain.adminEmail = os.Args[1]
	usrwtchmain.smtpServer = os.Args[2] + ":25"

	// initiate internal hash string used as semi-secret key to sign emails
	rnddata := randombytes(64)
	// copy to hashString
	copy(usrwtchmain.hashString[:], rnddata[:])

	// send email with secret hash string as hex (encrypt by admin public key?)
	var mailBody string = "Program restarted, current hash string: " + hex.EncodeToString(usrwtchmain.hashString[:])
	usrwtchmain.sendEmail(mailBody)

	// read /etc/passwd and /etc/shadow, calculate hash and store in struct
	usrwtchmain.passwdSig = usrwtchmain.gethash("/etc/passwd")
	//usrwtchmain.shadowSig = usrwtchmain.gethash("/etc/shadow")
	// read also old passwd in passwdBuf for diffs
	usrwtchmain.readPasswd()

	// main loop, setup dnotify and wait for changes in /etc/passwd and /etc/shadow
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()
	err = watcher.Add("/etc")
	if err != nil {
		panic(err)
	}
	/*
		err = watcher.Add("/etc/shadow")
		if err != nil {
			panic(err)
		}
	*/
	log.Println("Monitoring /etc/passwd and /etc/shadow for changes")
	//var passwdRemoved bool = false
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Println("Event:", event)
			// if write or create
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Println("File modified:", event.Name)
				// file was modified
				// check if /etc/passwd or /etc/shadow
				if event.Name == "/etc/passwd" {
					// generate diff and send email
					newPass, err := ioutil.ReadFile("/etc/passwd")
					if err != nil {
						panic(err)
					}
					usernames2 := getUsernames(newPass)
					var mailBody string = "----SIGNED----\n"
					// generate current datetime
					dateTime := getDateTime()
					mailBody += "Event time: " + dateTime + "\n"
					diff := cmpUsernames(usrwtchmain.usernames, usernames2)
					mailBody += diff
					mailBody += "\n----SIGNED----\n"
					// sign mailBody
					h := sha512.New()
					// use hashString as secret key
					h.Write(usrwtchmain.hashString[:])
					h.Write([]byte(mailBody))
					// copy hash to hashbuf
					var hashbuf [64]byte
					copy(hashbuf[:], h.Sum(nil))
					mailBody += "----HASH----\n"
					mailBody += hex.EncodeToString(hashbuf[:])
					mailBody += "\n----HASH----\n"
					if diff != "" {
						usrwtchmain.sendEmail(mailBody)
					}
					// TODO(nuclearcat): Provide simple way to verify email signature
					// update passwdBuf
					usrwtchmain.passwdBuf = newPass
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Error:", err)
		}
	}
}
