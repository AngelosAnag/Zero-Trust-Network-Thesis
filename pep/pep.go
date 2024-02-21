package main

import (
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

	"github.com/gorilla/mux"
)

// Change that to the appropriate container path
var certificatePathPrefix = "/home/angelos/Desktop/Thesis_Stuff/certificates/out/"

func loginHandlerRedirect(w http.ResponseWriter, r *http.Request) {
	// Send the login request to the / route on auth_server
	aggregateRequest("/login", "8080")
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(300)
}

// func resourceHandlerRedirect(w http.ResponseWriter, r *http.Request) {
// 	// Send the login request to the / route on dedicated resource
// 	aggregateRequest("/", "8082")
// }

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

func aggregateRequest(path, port string) {
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
	fmt.Printf("https://%s:%s%s", srvhost, port, path)
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

	router.Handle("/welcome", http.HandlerFunc(welcomeHandler))
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))
	http.Handle("/", router)
	http.HandleFunc("/login", loginHandlerRedirect)

	log.Printf("Starting HTTPS server on host %s and port %s", *host, *port)
	if err := server.ListenAndServeTLS(*serverCert, *srvKey); err != nil {
		log.Fatal(err)
	}
}
