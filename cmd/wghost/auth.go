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
	"errors"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/moapis/authenticator"
	"github.com/moapis/authenticator/verify"
	log "github.com/usrpro/clog15"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	auth   *verify.Verificator
	retErr = &verify.RetrieveError{}
	verErr = &verify.VerificationErr{}
)

func dialAuthenticator(ctx context.Context, target string, audiences ...string) (*verify.Verificator, error) {
	var (
		cc  *grpc.ClientConn
		err error
	)

	for cc == nil {
		if err = ctx.Err(); err != nil {
			return nil, err
		}

		// Local context enables retrying after every 5 seconds
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		cc, err = grpc.DialContext(ctx, target, grpc.WithBlock(), grpc.WithInsecure())
		switch err {
		case nil:
		case context.DeadlineExceeded:
			log15.Warn("dialAuthenticator", "err", err)
		default:
			return nil, err
		}
	}

	return &verify.Verificator{
		Client:    authenticator.NewAuthenticatorClient(cc),
		Audiences: audiences,
	}, nil
}

func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	jwt, ok := md["jwt"]
	if !ok || len(jwt) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Missing JWT in metadata")
	}

	log.Debug(ctx, "authInterceptor metadata", "jwt", jwt)

	claims, err := auth.Token(ctx, jwt[0])
	switch {
	case err == nil:
		log.Info(ctx, "Authenticated", "claims", claims)
		return handler(ctx, req)
	case errors.As(err, &retErr):
		log.Error(ctx, "authInterceptor RetrieveError", "err", err)
		return nil, status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &verErr):
		log.Warn(ctx, "authInterceptor VerificationErr", "err", err)
		return nil, status.Error(codes.Unauthenticated, err.Error())
	default:
		log.Error(ctx, "authInterceptor Unkown", "err", err)
		return nil, status.Error(codes.Unknown, "Unknown authentication error")
	}
}
