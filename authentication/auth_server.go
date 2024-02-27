package main

import (
	"authentication/utils"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	rdb "github.com/boj/redistore"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

// Change that to the appropriate container path
var certificatePathPrefix = "/home/angelos/Desktop/Thesis_Stuff/certificates/out/"

// var store *sessions.CookieStore
var store *rdb.RediStore
var sessionSecretKey = utils.InitSecretKey(filePath)

const (
	sessionName      = "user_session"
	contextKeyUserID = "user_id"
	filePath         = "/etc/profile.d/session_secret.sh"
)

func connectToRedis() {
	// Fetch new store.
	localstore, err := rdb.NewRediStore(10, "tcp", ":6379", "", []byte(sessionSecretKey))
	store = localstore
	if err != nil {
		panic(err)
	}
	// store = sessions.NewCookieStore([]byte(sessionSecretKey))
}

func getUserFromSession(r *http.Request, session *sessions.Session) (*utils.User, error) {

	// Retrieve user-specific information from the session
	_, ok := session.Values["user_id"].(int)
	if !ok {
		return nil, fmt.Errorf("user ID not found in session")
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return nil, fmt.Errorf("username not found in session")
	}

	user := utils.FindUser(utils.Users, username)
	return user, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Logout handler hello")

	// Get the user session
	session, err := store.Get(r, sessionName)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Clear the authenticated status in the session
	session.Values["authenticated"] = false

	// Delete the user session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to the login page after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// fmt.Println("Login handler hello")

	if r.Method != http.MethodPost {
		fmt.Println("Non Post request on login handler")
		http.Error(w, "GET request on POST endpoint", http.StatusBadRequest)
		return
	}

	session, err := store.Get(r, sessionName)
	fmt.Println(session.ID)

	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error setting user session", http.StatusInternalServerError)
		return
	}

	user, err := getUserFromSession(r, session)
	if err != nil {
		fmt.Println("Error retrieving user from session:", err)
		http.Error(w, "Error retrieving user from session", http.StatusInternalServerError)
		return
	}

	if user == nil {
		fmt.Println("User not found in session")
		http.Error(w, "User not found in session", http.StatusUnauthorized)
		return
	}

	fmt.Println(user.Username, user.Password)
	username, password := user.Username, user.Password

	// Should return an error value also
	utils.CreateUserObjectFromDB(username)
	// authenticatingUser := utils.FindUser(utils.Users, username)
	fmt.Println("Created user")

	// Password authentication
	if !utils.AuthenticateUser(username, password) {
		replyToPEP("/error", "8081")
		// http.Error(w, "Password authentication failed", http.StatusUnauthorized)
		return
	}
	fmt.Println("Accepted password")

	// Check fingerprint after successful password authentication
	fingerprintAuthenticator := &utils.MockFingerprintAuthenticator{}
	if fingerprintAuthenticator.CheckFingerprint(username) {
		// MFA completed, update the user status to authenticated and redirect to welcome page

		session.Values["authenticated"] = true

		// Reply to PEP
		replyToPEP("/welcome", "8081")
		return
	}

	replyToPEP("/error", "8081")
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// w.Write([]byte("Auth middleware hello"))
		// Check the user's authentication status
		session, err := store.Get(r, sessionName)

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if authenticated, ok := session.Values["authenticated"].(bool); !ok || !authenticated {
			// If not authenticated, redirect to the login page
			w.Write([]byte("Not authenticated!"))
			// http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		user, err := getUserFromSession(r, session)
		if err != nil || user == nil {
			http.Error(w, "Auth middleware log: Error retrieving user from session", http.StatusInternalServerError)
			return
		}

		// If authenticated, call the next handler
		next.ServeHTTP(w, r)
	})
}

func verifyHostMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedHost := "localhost"

		// Check if the request's host matches the allowed host
		if r.Host != allowedHost {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// If the host is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

func replyToPEP(path, port string) {

	srvhost := "localhost"
	caCertFile := certificatePathPrefix + "ThesisCA.crt"
	// These are indeed our server's keys, but being used to aggregate a request, we momentarily become a 'client' of shorts
	clientCertFile := certificatePathPrefix + "auth_server.crt"
	clientKeyFile := certificatePathPrefix + "auth_server.key"

	var cert tls.Certificate
	var err error
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			log.Fatalf("Error creating x509 keypair from client cert file %s and client key file %s", clientCertFile, clientKeyFile)
		}
	}

	// log.Printf("CAFile: %s", caCertFile)
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", caCertFile, err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	fmt.Printf("https://%s:%s%s", srvhost, port, path)

	client := http.Client{Transport: t, Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%s%s", srvhost, port, path), bytes.NewBuffer([]byte("")))
	if err != nil {
		log.Fatalf("unable to create http request due to error %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		switch e := err.(type) {
		case *url.Error:
			log.Fatalf("url.Error received on http request: %s", e)
		default:
			log.Fatalf("Unexpected error received: %s", err)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalf("unexpected error reading response body: %s", err)
	}

	fmt.Printf("\nResponse from server: \n\tHTTP status: %s\n\tBody: %s\n", resp.Status, body)
}

func main() {

	// Wait for request from PEP
	// Authenticate the user
	// Send the response back to PEP

	help := flag.Bool("help", false, "Optional, prints usage info")
	host := flag.String("host", "localhost", "Required flag, must be the hostname that is resolvable via DNS, or 'localhost'")
	port := flag.String("port", "8080", "The https port, running on 8080")
	serverCert := flag.String("srvcert", certificatePathPrefix+"localhost.crt", "Required, the name of the server's certificate file")
	caCert := flag.String("cacert", certificatePathPrefix+"ThesisCA.crt", "Required, the name of the CA that signed the client's certificate")
	srvKey := flag.String("srvKey", certificatePathPrefix+"localhost.key", "Required, the file name of the server's private key file")
	certOpt := flag.Int("certopt", 4, "Optional, specifies the option for authenticating a client via certificate")
	flag.Parse()

	usage := `usage:
	
simpleserver -host <hostname> -srvcert <serverCertFile> -cacert <caCertFile> -srvKey <serverPrivateKeyFile> [-port <port> -certopt <certopt> -help]
	
Options:
  -help       Prints this message
  -host       Required, a DNS resolvable host name
  -srvcert    Required, the name the server's certificate file
  -cacert     Required, the name of the CA that signed the client's certificate
  -srvKey     Required, the name the server's key certificate file
  -port       Optional, the https port for the server to listen on
  -certopt    Optional, specifies the option for authenticating a client via certificate:
			  0 - certificate not required, 
			  1 - request a certificate but it's not required,
			  2 - require any client certificate
			  3 - if provided, verify the client certificate is authorized
			  4 - require certificate and verify it's authorized`

	if *help {
		fmt.Println(usage)
		return
	}
	if *host == "" || *serverCert == "" || *caCert == "" || *srvKey == "" {
		log.Fatalf("One or more required fields missing:\n%s", usage)
	}

	if *certOpt < 0 || *certOpt > 4 {
		log.Fatalf("Invalid value %d, provided for 'certopt' flag. It must be a number between 0 and 4 inclusive.\n%s", *certOpt, usage)
	}

	server := &http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  5 * time.Minute, // 5 min to allow for delays when 'curl' on OSx prompts for username/password
		WriteTimeout: 10 * time.Second,
		TLSConfig:    utils.GetTLSConfig(*host, *caCert, tls.ClientAuthType(*certOpt)),
	}

	router := mux.NewRouter()

	// Protected routes, requiring user login
	router.Handle("/logout", authMiddleware(verifyHostMiddleware(http.HandlerFunc(logoutHandler)))).Methods(http.MethodGet)

	router.Handle("/login", http.HandlerFunc(loginHandler)).Methods(http.MethodPost, http.MethodGet)
	http.Handle("/", router)

	// Run the application server and connect to the sessions storage in goroutines
	go connectToRedis()
	log.Printf("Starting HTTPS server on host %s and port %s", *host, *port)
	if err := server.ListenAndServeTLS(*serverCert, *srvKey); err != nil {
		log.Fatal(err)
	}

	// err := http.ListenAndServe(":8080", nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

}
