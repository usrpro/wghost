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
