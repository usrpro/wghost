/*
This file is part wghost.

Wghost is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with wghost.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/usrpro/wghost"
	"github.com/usrpro/wghost/implement"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TLSConfig for the gRPC server's CertFile and KeyFile
type TLSConfig struct {
	CertFile string `json:"certfile,omitempty"`
	KeyFile  string `json:"keyfile,omitempty"`
}

// AuthServerConfig for the gRPC client connection
type AuthServerConfig struct {
	Host string
	Port uint16
}

func (ac *AuthServerConfig) String() string {
	return fmt.Sprintf("%s:%d", ac.Host, ac.Port)
}

// ServerConfig is a collection of config
type ServerConfig struct {
	Addres     string           `json:"address"`    // gRPC listen Address
	Port       uint16           `json:"port"`       // gRPC listen Port
	Device     string           `json:"device"`     // WireGuard device under management
	LogLevel   string           `json:"loglevel"`   // LogLevel used for log15
	TLS        *TLSConfig       `json:"tls"`        // TLS will be disabled when nil
	AuthServer AuthServerConfig `json:"authserver"` // Config for the gRPC client connection
	Audiences  []string         `json:"audiences"`  // Accepted audiences from JWT
}

func (c *ServerConfig) writeOut(filename string) error {
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, out, 0644)
}

// Default config
var Default = ServerConfig{
	Addres:     "127.0.0.1",
	Port:       8989,
	Device:     "wgtest",
	LogLevel:   "info",
	TLS:        nil,
	AuthServer: AuthServerConfig{"127.0.0.1", 8765},
	Audiences:  []string{"tester"},
}

func configure(c ServerConfig, configFiles string) (*ServerConfig, error) {
	files := strings.Split(configFiles, ",")
	s := &c
	for _, f := range files {
		if f == "" {
			continue
		}
		js, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("Read file %s: %w", f, err)
		}
		if err = json.Unmarshal(js, s); err != nil {
			return nil, fmt.Errorf("Unmarshal file %s: %w", f, err)
		}
	}

	return s, nil
}

func (c *ServerConfig) logger() (log15.Logger, error) {
	lvl, err := log15.LvlFromString(c.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("serverConfig.Logger: %w", err)
	}

	logger := log15.New()
	logger.SetHandler(
		log15.LvlFilterHandler(lvl, log15.StderrHandler),
	)

	return logger, nil
}

func (c *ServerConfig) grpcOpts() ([]grpc.ServerOption, error) {
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			logInterceptor,
			authInterceptor,
		),
	}

	if c.TLS != nil {
		cred, err := credentials.NewServerTLSFromFile(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(cred))
	}
	return opts, nil
}

func (c *ServerConfig) listenAndServe(sc <-chan os.Signal) error {
	logger, err := c.logger()
	if err != nil {
		return err
	}

	opts, err := c.grpcOpts()
	if err != nil {
		return err
	}

	gs := grpc.NewServer(opts...)
	wghost.RegisterWgServer(gs, implement.New(c.Device, logger))

	logger.Debug("Starting server", "conf", c, "grpc", gs.GetServiceInfo())

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.Addres, c.Port))
	if err != nil {
		return fmt.Errorf("listenAndServe: %w", err)
	}

	ec := make(chan error, 1)
	go func(ec chan<- error) {
		if err = gs.Serve(lis); err != nil {
			ec <- err
			return
		}
		ec <- nil
	}(ec)

	logger.Info("Server listening", "addr", c.Addres, "port", c.Port)

	select {
	case sig := <-sc:
		logger.Info("Stopping server", "sig", sig)
		gs.GracefulStop()
	case err = <-ec:
		return fmt.Errorf("listenAndServe: %w", err)
	}

	return nil
}
