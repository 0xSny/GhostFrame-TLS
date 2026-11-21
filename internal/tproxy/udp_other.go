//go:build !linux

package tproxy

import (
	"errors"
	"ghostframe/internal/client"
)

// UDPServer is a stub on non-Linux hosts; side-router UDP TPROXY requires Linux.
type UDPServer struct{}

func NewUDPServer(addr string, eng *client.Engine, modeFn func() GatewayMode) (*UDPServer, error) {
	return &UDPServer{}, nil
}

func (s *UDPServer) Start() error  { return errors.New("tproxy udp requires linux") }
func (s *UDPServer) Close()        {}
func (s *UDPServer) Count() uint64 { return 0 }
func (s *UDPServer) HasIPv6() bool { return false }
