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
)

// Change that to the appropriate container path
var certificatePathPrefix = "/home/angelos/Desktop/Thesis_Stuff/certificates/out/"

var store *rdb.RediStore
var sessionSecretKey = utils.InitSecretKey(filePath)

const (
	sessionName      = "user_session"
	contextKeyUserID = "user_id"
	filePath         = "/etc/profile.d/session_secret.sh"
)

func setUserSession(w http.ResponseWriter, r *http.Request, user *utils.User) error {
	// Create a new session
	session, err := store.New(r, sessionName)
	if err != nil {
		return err
	}

	// Store user-specific information in the session
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["authenticated"] = false
	session.Values["trust_lvl"] = user.TrustLevel
	session.Values["groups"] = user.Groups

	// Save the session
	if err := session.Save(r, w); err != nil {
		return err
	}

	return nil
}

func connectToRedis() {
	// Fetch new store.
	localstore, err := rdb.NewRediStore(10, "tcp", ":6379", "", []byte(sessionSecretKey))
	store = localstore
	if err != nil {
		panic(err)
	}
	// store = sessions.NewCookieStore([]byte(sessionSecretKey))
}

func loginHandlerRedirect(w http.ResponseWriter, r *http.Request) {

	// Should connect to redis, create the store and set the user session here.
	username := r.FormValue("username")
	password := r.FormValue("password")

	fmt.Println(username, password)

	aggregateRequest(w, r, "/login", "8080")
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/error.html")
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Welcome handler hello")
	http.ServeFile(w, r, "templates/welcome.html")
}

func authResponseReceiver(w http.ResponseWriter, r *http.Request) {

	// Forward response back to client
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	respBody := buf.String()

	w.WriteHeader(205)
	w.Write([]byte(respBody))
}

func getTLSConfig(host, caCertFile string, certOpt tls.ClientAuthType) *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool
	if certOpt > tls.RequestClientCert {
		caCert, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			log.Fatal("Error opening cert file", caCertFile, ", error ", err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	return &tls.Config{
		ServerName: host,
		// ClientAuth: tls.NoClientCert,				// Client certificate will not be requested and it is not required
		// ClientAuth: tls.RequestClientCert,			// Client certificate will be requested, but it is not required
		// ClientAuth: tls.RequireAnyClientCert,		// Client certificate is required, but any client certificate is acceptable
		// ClientAuth: tls.VerifyClientCertIfGiven,		// Client certificate will be requested and if present must be in the server's Certificate Pool
		// ClientAuth: tls.RequireAndVerifyClientCert,	// Client certificate will be required and must be present in the server's Certificate Pool
		ClientAuth: certOpt,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}
}

func aggregateRequest(w http.ResponseWriter, r *http.Request, path, port string) {
	// This function should take another argument as input, which would be the host to which we re aggregating to
	// On testing everything is done to localhost so this step is optional
	// The request is aggregated to localhost but this is basically our auth_server
	// Right now we re only changing the ports, in containers everything should run normally at 443 by changing the hostnames
	// Probably... maybe... hopefully...
	srvhost := "localhost"
	caCertFile := certificatePathPrefix + "ThesisCA.crt"
	// These are indeed our server's keys, but being used to aggregate a request, we momentarily become a 'client' of shorts
	clientCertFile := certificatePathPrefix + "localhost.crt"
	clientKeyFile := certificatePathPrefix + "localhost.key"

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

	client := http.Client{Transport: t, Timeout: 15 * time.Second}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// you can reassign the body if you need to parse it as multipart
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	proxy_url := fmt.Sprintf("https://%s:%s%s", srvhost, port, path)
	fmt.Println(proxy_url)

	req, err := http.NewRequest(r.Method, proxy_url, bytes.NewReader(body))

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
	defer resp.Body.Close()

	fmt.Printf("\nResponse from server: \n\tHTTP status: %s\n\tBody: %s\n", resp.Status, resp.Body)
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

func main() {

	// Display a page with available resources for user to pick from
	// Create session cookie for user to be managed by portals
	// Receive response and redirect user to authentication portal
	// Receive response and redirect to authorization portal
	// Receive response and redirect to resource
	// Delete session cookie and close the connection

	help := flag.Bool("help", false, "Optional, prints usage info")
	// Hosts should become the container names in the future, remember to also change the keys and certificate values
	host := flag.String("host", "localhost", "Required flag, must be the hostname that is resolvable via DNS, or 'localhost'")
	port := flag.String("port", "8081", "The https port, defaults to 443, we use 8081")
	serverCert := flag.String("srvcert", certificatePathPrefix+"localhost.crt", "Required, the name of the server's certificate file")
	caCert := flag.String("cacert", certificatePathPrefix+"ThesisCA.crt", "Required, the name of the CA that signed the client's certificate")
	srvKey := flag.String("srvKey", certificatePathPrefix+"localhost.key", "Required, the file name of the server's private key file")
	certOpt := flag.Int("certopt", 4, "Optional, specifies the option for authenticating a client via certificate")
	flag.Parse()

	usage := `usage:
	
simpleserver -host <hostname> -srvcert <serverCertFile> -cacert <caCertFile> -srvkey <serverPrivateKeyFile> [-port <port> -certopt <certopt> -help]
	
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
		TLSConfig:    getTLSConfig(*host, *caCert, tls.ClientAuthType(*certOpt)),
	}

	router := mux.NewRouter()

	router.Handle("/gateway-login", http.HandlerFunc(loginHandlerRedirect)).Methods(http.MethodPost)
	router.Handle("/authResponse", http.HandlerFunc(authResponseReceiver))
	router.Handle("/welcome", verifyHostMiddleware(http.HandlerFunc(welcomeHandler))) // Only allow welcome route from Auth server
	router.Handle("/error", http.HandlerFunc(errorHandler))

	router.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))
	http.Handle("/", router)

	log.Printf("Starting HTTPS server on host %s and port %s", *host, *port)
	if err := server.ListenAndServeTLS(*serverCert, *srvKey); err != nil {
		log.Fatal(err)
	}
}
