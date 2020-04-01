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
	"context"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/inconshreveable/log15/ext"
	log "github.com/usrpro/clog15"
	"github.com/usrpro/wghost/implement"
	"google.golang.org/grpc"
)

func logInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	s, ok := info.Server.(implement.WgDeviceServer)
	if ok {
		ctx = log.SetLogger(ctx, s.Logger(), "id", ext.RandId(4), "method", info.FullMethod)
	}

	return handler(ctx, req)
}

var configFiles = flag.String("config", "", "Comma separated list of JSON config files")

func run(sc <-chan os.Signal) int {
	conf, err := configure(Default, *configFiles)
	if err != nil {
		log15.Crit("Main", "err", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if auth, err = dialAuthenticator(ctx, conf.AuthServer.String()); err != nil {
		log15.Crit("Main", "err", err)
		return 1
	}

	if err = conf.listenAndServe(sc); err != nil {
		log15.Crit("Main", "err", err)
		return 1
	}
	return 0
}

func main() {
	flag.Parse()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)

	os.Exit(run(sc))
}
