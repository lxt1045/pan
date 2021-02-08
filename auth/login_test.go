package auth

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/jsyzchen/pan/conf"
)

func TestAuth_OAuthUrl2(t *testing.T) {
	authClient := NewAuthClient(conf.TestData.ClientID, conf.TestData.ClientSecret)
	res, err := authClient.OAuthUrl2(conf.TestData.RedirectUri)
	if err != nil {
		t.Fatal(res, "  ", err)
	}
	t.Logf("TestAuth_OAuthUrl res: %+v", res)
}

func TestAuth_OAuthUrl3(t *testing.T) {
	authClient := NewAuthClient(conf.TestData.ClientID, conf.TestData.ClientSecret)
	res, err := authClient.OAuthUrl3(conf.TestData.RedirectUri)
	if err != nil {
		t.Fatal(res, "  ", err)
	}
	t.Logf("TestAuth_OAuthUrl res: %+v", res)
}

func TestAuth_Login(t *testing.T) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("What is your name:")
	data, _, _ := reader.ReadLine()
	fmt.Printf("Your name is %s.\r\n", data)

	cookies, err := Login("", "")
	if err != nil {
		t.Fatal(cookies, err)
	}
	t.Logf("cookies: %+v", cookies)
}
