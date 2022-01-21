// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Prints the TOML configuration file.
	// (GET /config)
	GetConfig(w http.ResponseWriter, r *http.Request)
	// Basic information page about the control service process.
	// (GET /info)
	GetInfo(w http.ResponseWriter, r *http.Request)
	// List the SCION interfaces
	// (GET /interfaces)
	GetInterfaces(w http.ResponseWriter, r *http.Request)
	// Get logging level
	// (GET /log/level)
	GetLogLevel(w http.ResponseWriter, r *http.Request)
	// Set logging level
	// (PUT /log/level)
	SetLogLevel(w http.ResponseWriter, r *http.Request)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
}

type MiddlewareFunc func(http.HandlerFunc) http.HandlerFunc

// GetConfig operation middleware
func (siw *ServerInterfaceWrapper) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetConfig(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// GetInfo operation middleware
func (siw *ServerInterfaceWrapper) GetInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetInfo(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// GetInterfaces operation middleware
func (siw *ServerInterfaceWrapper) GetInterfaces(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetInterfaces(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// GetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetLogLevel(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// SetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.SetLogLevel(w, r)
	}

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler(w, r.WithContext(ctx))
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL     string
	BaseRouter  chi.Router
	Middlewares []MiddlewareFunc
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/config", wrapper.GetConfig)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/info", wrapper.GetInfo)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/interfaces", wrapper.GetInterfaces)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/log/level", wrapper.GetLogLevel)
	})
	r.Group(func(r chi.Router) {
		r.Put(options.BaseURL+"/log/level", wrapper.SetLogLevel)
	})

	return r
}
