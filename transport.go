package goauthcli

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"code.google.com/p/goauth2/oauth"
)

func GetTransport(config *oauth.Config, httpListenAddress string) (*oauth.Transport, error) {

	transport := &oauth.Transport{Config: config}

	if config.TokenCache != nil {
		token, err := config.TokenCache.Token()
		if err != nil {
			fmt.Printf("Error loading from cache: %s\n", err.Error())
		} else {
			transport.Token = token
		}
	}

	if transport.Token != nil && !transport.Token.Expired() {
		return transport, nil
	}

	fmt.Println("Token is nil or expired")
	fmt.Println(config.AccessType)

	if config.AccessType == "offline" {
		err := transport.Refresh()
		if err != nil {
			log.Printf("Error refreshing transport: %s\n", err.Error())
		}
		if transport.Token != nil && !transport.Token.Expired() {
			return transport, nil
		}
	}

	chanDone := make(chan bool)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if transport.Token == nil || transport.Token.Expired() {
			url := config.AuthCodeURL("")
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprintf(w, "Transport OK, Expires %s\n", transport.Expiry.String())
	})

	http.HandleFunc("/oauth2callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		log.Println(code)
		token, err := transport.Exchange(code)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		transport.Token = token
		http.Redirect(w, r, "/auth", http.StatusTemporaryRedirect)
		chanDone <- true
	})

	ln, err := net.Listen("tcp", httpListenAddress)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Visit %s to authorise\n", httpListenAddress)
	go func() {
		http.Serve(ln, nil)
	}()
	_ = <-chanDone
	ln.Close()
	fmt.Println("Authorised")
	return transport, nil
}
