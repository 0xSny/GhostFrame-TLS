//go:build !linux

package tproxy

import (
	"errors"
	"ghostframe/internal/client"
)

// TCPServer is a stub on non-Linux hosts; side-router TPROXY requires Linux.
type TCPServer struct{}

func NewTCPServer(addr string, eng *client.Engine, modeFn func() GatewayMode) (*TCPServer, error) {
	return &TCPServer{}, nil
}

func (s *TCPServer) Start() error  { return errors.New("tproxy tcp requires linux") }
func (s *TCPServer) Close()        {}
func (s *TCPServer) Count() uint64 { return 0 }
func (s *TCPServer) HasIPv6() bool { return false }
