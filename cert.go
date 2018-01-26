package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/pkg/errors"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatal("missing url arg")
	}

	chains, err := getChains(os.Args[1])
	if err != nil {
		log.Fatalf("error getting chains: %v", err)
	}

	dumpChains(chains)
}

func getChains(url string) (certs [][]*x509.Certificate, err error) {
	conf := &tls.Config{}
	conn, err := tls.Dial("tcp", url, conf)
	if err != nil {
		return nil, errors.Wrap(err, "error dialling remote endpoint")
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			err = errors.Wrap(cerr, "error closing connection")
		}
	}()
	if err = conn.Handshake(); err != nil {
		return nil, errors.Wrap(err, "error performing handshake")
	}

	return conn.ConnectionState().VerifiedChains, nil
}

func dumpChains(chains [][]*x509.Certificate) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Issuer\tSHA256")
	for _, chain := range chains {
		for _, cert := range chain {
			raw := sha256.Sum256(cert.Raw)
			fmt.Fprintf(w, "%s\t%x\n", cert.Issuer.CommonName, raw[:])
		}
	}
	w.Flush()
}
