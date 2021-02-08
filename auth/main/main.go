package main

import (
	"log"

	"github.com/jsyzchen/pan/auth"
)

func init() {
	log.SetFlags(log.Flags() | log.Lmicroseconds | log.Lshortfile) //log.Llongfile
}

func main() {

	cookies, err := auth.Login("", "")
	if err != nil {
		log.Fatal(cookies, err)
	}
	log.Printf("cookies: %+v", cookies)

	a := auth.NewAuthClient("", "")
	ret, err := a.OAuthUrl4(cookies)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("xx:%+v", ret)
}
