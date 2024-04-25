// A simple webpage with protected endpoints in Go, admin and user accounts have different access levels

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

var routesMap = map[string]string{
	"/admin-resource": "protected",
	"/user-resource":  "unprotected",
}

func mfaHandler(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/bio-mfa/auth", http.StatusTemporaryRedirect)
}

func protectedResourceHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello from protected resource\nFor admin eyes only!"))
}

func unprotectedResourceHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello from unprotected resource\nPlain for all to see!"))
}

func MFAMiddleware(next http.Handler) http.Handler {
	// Check if the user is authenticated with MFA via his cookie
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("user-session")
		if err != nil {
			http.Error(w, "No cookie found", http.StatusUnauthorized)
			return
		}
		passedMFA := cookie.Value
		clickedLink := req.Header.Get("X-Forwarded-Path")

		if passedMFA == "authenticated" {
			next.ServeHTTP(w, req)
		} else {
			http.Redirect(w, req, "/bio-mfa/auth?redirect="+clickedLink, http.StatusSeeOther)
			return
		}
	})
}

func authorizationMiddleware(next http.Handler) http.Handler {
	// Check the user type and his access level
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Println(req.Header)
		userType := req.Header.Get("X-Consumer-Custom-Id")
		resourceTag := routesMap[req.URL.Path]

		// This serves as our ACL but is a simple OR statement since we only have 2 users
		if (resourceTag == "unprotected") || (resourceTag == "protected" && userType == "admin") {
			next.ServeHTTP(w, req)
		} else {
			http.Error(w, "Not an admin", http.StatusForbidden)
			return
		}

	})
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

var certificatePathPrefix = "/home/angelos/Desktop/ThesisRevived/certificates/out/"

func main() {
	help := flag.Bool("help", false, "Optional, prints usage info")
	// Hosts should become the container names in the future, remember to also change the keys and certificate values
	host := flag.String("host", "localhost", "Required flag, must be the hostname that is resolvable via DNS, or 'localhost'")
	port := flag.String("port", "3001", "The https port, defaults to 443")
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

	//Serves an html page with server's resources
	fs := http.FileServer(http.Dir("./static"))
	router.Handle("/", fs)

	router.Handle("/mfa-redirect", http.HandlerFunc(mfaHandler))

	// This is where basic IAM is performed, however both user types (admin/user)
	// have to pass MFA in order to view resources
	router.Handle("/admin-resource", MFAMiddleware(authorizationMiddleware(http.HandlerFunc(protectedResourceHandler))))
	router.Handle("/user-resource", MFAMiddleware(authorizationMiddleware(http.HandlerFunc(unprotectedResourceHandler))))

	http.Handle("/", router)

	log.Printf("Starting HTTPS server on host %s and port %s", *host, *port)
	if err := server.ListenAndServeTLS(*serverCert, *srvKey); err != nil {
		log.Fatal(err)
	}
}
