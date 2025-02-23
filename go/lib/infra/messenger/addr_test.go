// Copyright 2019 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package messenger_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/messenger/mock_messenger"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestRedirectQUIC(t *testing.T) {
	dummyIA := xtest.MustParseIA("1-ff00:0:2")
	testCases := map[string]struct {
		input                 net.Addr
		wantAddr              net.Addr
		wantRedirect          bool
		SVCResolutionFraction float64
		assertErr             assert.ErrorAssertionFunc
	}{
		"nil addr, no error": {
			input:     nil,
			wantAddr:  nil,
			assertErr: assert.NoError,
		},
		"not nil invalid addr, error": {
			input:                 &net.TCPAddr{},
			wantAddr:              nil,
			wantRedirect:          false,
			SVCResolutionFraction: 1.0,
			assertErr:             assert.Error,
		},
		"valid UDPAddr, returns unchanged": {
			input:                 &snet.UDPAddr{IA: dummyIA, Host: &net.UDPAddr{}},
			wantAddr:              &snet.UDPAddr{IA: dummyIA, Host: &net.UDPAddr{}},
			wantRedirect:          false,
			SVCResolutionFraction: 1.0,
			assertErr:             assert.NoError,
		},
	}
	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			router := mock_snet.NewMockRouter(ctrl)
			router.EXPECT().Route(gomock.Any(), gomock.Any()).Times(0)
			resolver := mock_messenger.NewMockResolver(ctrl)
			resolver.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			aw := messenger.AddressRewriter{
				Resolver:              resolver,
				Router:                router,
				SVCResolutionFraction: tc.SVCResolutionFraction,
			}

			a, r, err := aw.RedirectToQUIC(context.Background(), tc.input)
			tc.assertErr(t, err)
			assert.Equal(t, a, tc.wantAddr)
			assert.Equal(t, r, tc.wantRedirect)
		})
	}

	t.Run("Fraction 0.5, returns no error", func(t *testing.T) {
		t.Log("svc address, half time allowed for resolution, lookup fails")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		resolver := mock_messenger.NewMockResolver(ctrl)
		resolver.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("lookups errors"))
		path := mock_snet.NewMockPath(ctrl)
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
		path.EXPECT().Dataplane().Return(snetpath.SCION{})
		path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{IP: net.ParseIP("10.1.1.1")})
		path.EXPECT().Metadata().Return(&snet.PathMetadata{
			Interfaces: make([]snet.PathInterface, 1), // just non-empty
		})

		aw := messenger.AddressRewriter{
			Router:                router,
			Resolver:              resolver,
			SVCResolutionFraction: 0.5,
		}

		input := &snet.SVCAddr{IA: dummyIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		want := &snet.SVCAddr{
			IA:      dummyIA,
			NextHop: &net.UDPAddr{IP: net.ParseIP("10.1.1.1")},
			SVC:     addr.SvcCS,
			Path:    snetpath.SCION{},
		}
		a, r, err := aw.RedirectToQUIC(context.Background(), input)
		assert.NoError(t, err)
		assert.Equal(t, want, a)
		assert.False(t, r)
	})

	t.Run("valid SVCAddr, returns no error and UPDAddr", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		resolver := mock_messenger.NewMockResolver(ctrl)
		resolver.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&svc.Reply{
				Transports: map[svc.Transport]string{svc.QUIC: "192.168.1.1:8000"},
				ReturnPath: &testPath{},
			}, nil)
		path := mock_snet.NewMockPath(ctrl)
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
		path.EXPECT().Dataplane().Return(snetpath.SCION{})
		path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{IP: net.ParseIP("10.1.1.1")})
		path.EXPECT().Metadata().Return(&snet.PathMetadata{
			Interfaces: make([]snet.PathInterface, 1), // just non-empty
		})

		aw := messenger.AddressRewriter{
			Router:                router,
			Resolver:              resolver,
			SVCResolutionFraction: 1,
		}

		input := &snet.SVCAddr{IA: dummyIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		want := &snet.UDPAddr{
			IA:      dummyIA,
			Path:    snetpath.SCION{},
			NextHop: &net.UDPAddr{IP: net.ParseIP("10.1.1.1")},
			Host:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8000},
		}
		a, r, err := aw.RedirectToQUIC(context.Background(), input)
		assert.NoError(t, err)
		assert.Equal(t, want, a)
		assert.True(t, r)
	})

	t.Run("valid SVCAddr, no resolution, resolves path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)

		path := mock_snet.NewMockPath(ctrl)
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
		path.EXPECT().Dataplane().Return(snetpath.SCION{})
		path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{IP: net.ParseIP("10.1.1.1")})
		path.EXPECT().Metadata().Return(&snet.PathMetadata{})
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		svcRouter.EXPECT().GetUnderlay(addr.SvcCS).Return(
			&net.UDPAddr{IP: net.ParseIP("10.1.1.1")}, nil,
		)

		aw := messenger.AddressRewriter{
			Router:                router,
			SVCRouter:             svcRouter,
			SVCResolutionFraction: 0.0,
		}

		input := &snet.SVCAddr{SVC: addr.SvcCS, Path: snetpath.Empty{}}
		want := &snet.SVCAddr{
			SVC:     addr.SvcCS,
			NextHop: &net.UDPAddr{IP: net.ParseIP("10.1.1.1")},
			Path:    snetpath.SCION{},
		}
		a, r, err := aw.RedirectToQUIC(context.Background(), input)
		assert.NoError(t, err)
		assert.Equal(t, want, a)
		assert.False(t, r)
	})
}

func TestBuildFullAddress(t *testing.T) {
	t.Run("snet address without path, error retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}
		input := &snet.SVCAddr{IA: remoteIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("err"))
		_, err := aw.BuildFullAddress(context.Background(), input)
		assert.Error(t, err)
	})

	t.Run("snet address with path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		input := &snet.SVCAddr{
			IA:   remoteIA,
			Path: snetpath.SCION{},
			SVC:  addr.SvcCS,
		}
		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Equal(t, a, input)
		assert.NoError(t, err)
	})

	t.Run("snet address without path, successful retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Dataplane().Return(snetpath.SCION{})
		path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{})
		path.EXPECT().Metadata().Return(&snet.PathMetadata{
			Interfaces: make([]snet.PathInterface, 1), // just non-empty
		})
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
		input := &snet.SVCAddr{IA: remoteIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		a, err := aw.BuildFullAddress(context.Background(), input)
		want := &snet.SVCAddr{
			IA:      remoteIA,
			Path:    snetpath.SCION{},
			NextHop: &net.UDPAddr{},
			SVC:     addr.SvcCS,
		}
		assert.Equal(t, a, want)
		assert.NoError(t, err)
	})

	t.Run("snet address in local AS, underlay address extraction succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		localIA := xtest.MustParseIA("1-ff00:0:1")
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		underlayAddr := &net.UDPAddr{
			IP:   net.IP{192, 168, 0, 1},
			Port: 10,
		}
		svcRouter.EXPECT().GetUnderlay(addr.SvcCS).Return(underlayAddr, nil)

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Metadata().Return(&snet.PathMetadata{})
		path.EXPECT().Dataplane()
		path.EXPECT().UnderlayNextHop()
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)

		input := &snet.SVCAddr{IA: localIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		a, err := aw.BuildFullAddress(context.Background(), input)

		want := &snet.SVCAddr{IA: localIA, NextHop: underlayAddr, SVC: addr.SvcCS}
		assert.Equal(t, a, want)
		assert.NoError(t, err)
	})

	t.Run("snet address in local AS, underlay address extraction fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		localIA := xtest.MustParseIA("1-ff00:0:1")
		svcRouter := mock_messenger.NewMockSVCResolver(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		svcRouter.EXPECT().GetUnderlay(addr.SvcCS).Return(nil, errors.New("err"))

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Metadata().Return(&snet.PathMetadata{})
		path.EXPECT().Dataplane()
		path.EXPECT().UnderlayNextHop()
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)

		input := &snet.SVCAddr{IA: localIA, SVC: addr.SvcCS, Path: snetpath.Empty{}}
		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Nil(t, a)
		assert.Error(t, err)
	})
}

func TestResolve(t *testing.T) {
	testCases := map[string]struct {
		input                 addr.HostSVC
		ResolverSetup         func(*mock_messenger.MockResolver)
		SVCResolutionFraction float64
		wantPath              snet.Path
		want                  *net.UDPAddr
		wantQUICRedirect      bool
		assertErr             assert.ErrorAssertionFunc
	}{
		"svc address, lookup fails": {
			input: addr.SvcCS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 1.0,
			assertErr:             assert.Error,
		},
		"svc address, lookup succeeds": {
			input: addr.SvcCS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(
						&svc.Reply{
							Transports: map[svc.Transport]string{
								svc.QUIC: "192.168.1.1:8000",
							},
							ReturnPath: &testPath{},
						},
						nil,
					)
			},
			SVCResolutionFraction: 1.0,
			wantPath:              &testPath{},
			want:                  &net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000},
			wantQUICRedirect:      true,
			assertErr:             assert.NoError,
		},
		"svc address, half time allowed for resolution, lookup succeeds": {
			input: addr.SvcCS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(
						&svc.Reply{
							Transports: map[svc.Transport]string{
								svc.QUIC: "192.168.1.1:8000",
							},
						},
						nil,
					)
			},
			SVCResolutionFraction: 0.5,
			want:                  &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8000},
			wantQUICRedirect:      true,
			assertErr:             assert.NoError,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			resolver := mock_messenger.NewMockResolver(ctrl)
			path := mock_snet.NewMockPath(ctrl)
			path.EXPECT().Destination().Return(addr.IA(0)).AnyTimes()
			aw := messenger.AddressRewriter{
				Resolver:              resolver,
				SVCResolutionFraction: tc.SVCResolutionFraction,
			}
			initResolver(resolver, tc.ResolverSetup)
			p, a, redirect, err := aw.ResolveSVC(context.Background(), path, tc.input)
			assert.Equal(t, p, tc.wantPath)
			assert.Equal(t, a.String(), tc.want.String())
			assert.Equal(t, redirect, tc.wantQUICRedirect)
			tc.assertErr(t, err)
		})
	}
}

func TestParseReply(t *testing.T) {
	testCases := map[string]struct {
		mockReply *svc.Reply
		want      *net.UDPAddr
		assertErr assert.ErrorAssertionFunc
	}{
		"nil reply": {
			assertErr: assert.Error,
		},
		"empty reply": {
			mockReply: &svc.Reply{},
			assertErr: assert.Error,
		},
		"key not found in reply": {
			mockReply: &svc.Reply{Transports: map[svc.Transport]string{"UNKNOWN": "foo"}},
			assertErr: assert.Error,
		},
		"key found in reply, but parsing fails": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "foo",
				},
			},
			assertErr: assert.Error,
		},
		"key found in reply, IPv4 address": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "192.168.1.1:8000",
				},
			},
			want:      &net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000},
			assertErr: assert.NoError,
		},
		"key found in reply, IPv6 address": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "[2001:db8::1]:8000",
				},
			},
			want:      &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8000},
			assertErr: assert.NoError,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			a, err := messenger.ParseReply(tc.mockReply)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, a.String(), tc.want.String())
		})
	}
}

func initResolver(resolver *mock_messenger.MockResolver, f func(*mock_messenger.MockResolver)) {
	if f != nil {
		f(resolver)
	}
}

type testPath struct{}

func (t *testPath) UnderlayNextHop() *net.UDPAddr {
	panic("not implemented")
}

func (t *testPath) Dataplane() snet.DataplanePath {
	return snetpath.SCION{}
}

func (t *testPath) Destination() addr.IA {
	panic("not implemented")
}

func (t *testPath) Metadata() *snet.PathMetadata {
	panic("not implemented")
}

func (t *testPath) Copy() snet.Path {
	panic("not implemented")
}
