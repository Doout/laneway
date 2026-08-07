package controllerservice

import (
	"crypto/tls"
	"net/http"
	"time"
)

// NewHTTPServer returns a production-bounded server. TLS is mandatory at the
// call site via ListenAndServeTLS or ServeTLS; VerifyClientCertIfGiven permits
// unauthenticated enrollment while verifying certificates on node endpoints.
func (s *Service) NewHTTPServer(address string, tlsConfig *tls.Config) *http.Server {
	config := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven}
	if tlsConfig != nil {
		config = tlsConfig.Clone()
		if config.MinVersion < tls.VersionTLS13 {
			config.MinVersion = tls.VersionTLS13
		}
	}
	// Enrollment has no client certificate. Other handlers enforce a verified
	// node certificate at application authorization time.
	config.ClientAuth = tls.VerifyClientCertIfGiven
	return &http.Server{
		Addr: address, Handler: s.Handler(), TLSConfig: config,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}
