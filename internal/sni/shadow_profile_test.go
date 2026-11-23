package sni

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestProbeCamouflageProfileCapturesTLS13MetadataAndTickets(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"origin.shadow.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
		CurvePreferences: []tls.CurveID{tls.X25519},
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		tc := tls.Server(c, srvCfg)
		if herr := tc.Handshake(); herr != nil {
			return
		}
		// Keep connection open briefly so client drains post-handshake NewSessionTicket records.
		var buf [64]byte
		_ = tc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = tc.Read(buf[:])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	prof, err := ProbeCamouflageProfile(ctx, ln.Addr().String(), "origin.shadow.test")
	if err != nil {
		t.Fatalf("ProbeCamouflageProfile failed: %v", err)
	}
	<-done

	if prof.CipherSuite == 0 {
		t.Fatalf("expected non-zero CipherSuite, got %+v", prof)
	}
	if prof.KeyShareGroup != uint16(tls.X25519) {
		t.Fatalf("expected KeyShareGroup X25519 (0x001d), got 0x%04x", prof.KeyShareGroup)
	}
	if !reflect.DeepEqual(prof.ServerHelloExtOrder, []uint16{0x002b, 0x0033}) &&
		!reflect.DeepEqual(prof.ServerHelloExtOrder, []uint16{0x0033, 0x002b}) {
		t.Fatalf("unexpected ServerHelloExtOrder: %x", prof.ServerHelloExtOrder)
	}
	if len(prof.Flight2RecordLens) < 4 {
		t.Fatalf("expected >=4 Flight2 records (EE/Cert/CertVerify/Finished), got %+v", prof)
	}
	if prof.ALPN != "h2" {
		t.Fatalf("expected ALPN=h2, got %q", prof.ALPN)
	}
	_ = binary.BigEndian
}
