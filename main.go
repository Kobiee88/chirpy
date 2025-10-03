package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add a simple handler for the health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Serve the static HTML file
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("."))))

	// Create the server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Starting server on localhost:8080...")
	log.Fatal(server.ListenAndServe())
}
