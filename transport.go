package goauthcli

import (
	"fmt"
	"net"
	"net/http"

	"code.google.com/p/goauth2/oauth"
)

// GetTransport returns an oauth transport with a valid, not expired token.
// GetTransport will create a mini-server on httpListenAddress for the client
// authentication flow.
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

	if config.AccessType == "offline" {
		err := transport.Refresh()
		if err != nil {
			fmt.Printf("Error refreshing transport: %s\n", err.Error())
		}
		if transport.Token != nil && !transport.Token.Expired() {
			return transport, nil
		}

	}

	chanDone := make(chan bool)

	if len(httpListenAddress) < 1 {
		return nil, fmt.Errorf("No token available, and no listen address specified")
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if transport.Token == nil || transport.Token.Expired() {
			url := config.AuthCodeURL("")
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprintf(w, "Transport OK, Expires %s\n", transport.Expiry.String())
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		fmt.Printf("CODE RESPONSE %s\n", code)
		token, err := transport.Exchange(code)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		fmt.Printf("REFRESH TOKEN = %s\n", token.RefreshToken)
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
