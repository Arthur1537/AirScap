// Command vensim runs the VENS scanner simulator (internal/vens/vensim) for
// isolated end-to-end tests. Test tool only: not built into the production
// image (the Dockerfile builds ./cmd/airscap).
//
//	vensim -ip 127.0.0.2 -serial iX500-SIM0001 -control 127.0.0.1:9099
//
// Control API (no authentication; bind it to loopback or a test network):
//
//	GET  /health    {"paired": bool}
//	POST /profile   vensim.Profile as JSON
//	POST /press     scan button
//	POST /offline   scanner leaves the network
//	POST /online    scanner returns
//	GET  /requests  recorded requests
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/mzyy94/airscap/internal/vens/vensim"
)

func main() {
	ip := flag.String("ip", "127.0.0.2", "address to listen on and to advertise")
	serial := flag.String("serial", "iX500-SIM0001", "serial (default password: its last 4 characters)")
	password := flag.String("password", "", "pairing password (default from serial)")
	control := flag.String("control", "127.0.0.1:9099", "control API address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sim, err := vensim.Start(ctx, vensim.Config{IP: *ip, Serial: *serial, Password: *password}, vensim.Profile{Sheets: 1})
	if err != nil {
		log.Fatal(err)
	}
	defer sim.Close()
	server := &http.Server{Addr: *control, Handler: handler(ctx, sim)}
	go func() { <-ctx.Done(); server.Close() }()
	log.Printf("vensim: scanner %s, control http://%s", *ip, *control)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func handler(ctx context.Context, sim *vensim.Simulator) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, err error, body any) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			body = map[string]string{"error": err.Error()}
		}
		json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, nil, map[string]bool{"paired": sim.Paired()})
	})
	mux.HandleFunc("POST /profile", func(w http.ResponseWriter, r *http.Request) {
		var p vensim.Profile
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			http.Error(w, "invalid profile", http.StatusBadRequest)
			return
		}
		sim.SetProfile(p)
		reply(w, nil, p)
	})
	mux.HandleFunc("POST /press", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, sim.PressButton(), map[string]string{"status": "pressed"})
	})
	mux.HandleFunc("POST /offline", func(w http.ResponseWriter, _ *http.Request) {
		sim.GoOffline()
		reply(w, nil, map[string]string{"status": "offline"})
	})
	mux.HandleFunc("POST /online", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, sim.GoOnline(ctx), map[string]string{"status": "online"})
	})
	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, nil, sim.Requests())
	})
	return mux
}
