package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/Kobiee88/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
}

func main() {
	// Create an instance of apiConfig
	apiCfg := apiConfig{}

	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

	// Connect to the database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	apiCfg.dbQueries = database.New(db)
	apiCfg.platform = platform

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add a simple handler for the health check endpoint
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(http.StatusText(http.StatusOK)))
	})

	// Add a handler to display the metrics
	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", apiCfg.fileserverHits.Load())))
	})

	// Add a handler to reset the metrics
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		apiCfg.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hits reset to 0"))

		if apiCfg.platform == "dev" {
			// In dev environment, also clear the users table
			err := apiCfg.dbQueries.DeleteUsers(r.Context())
			if err != nil {
				log.Printf("Error deleting users from database: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error deleting users from database"))
				return
			}
			log.Printf("All users deleted from database")
		} else {
			log.Printf("User deletion skipped: not in dev environment")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("User deletion is only allowed in dev environment"))
		}
	})

	// Add a handler to except POST request as JSON body to create a chirp
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Body   string `json:"body"`
			UserID string `json:"user_id"`
		}
		var params parameters

		type returnData struct {
			Id          string `json:"id"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
			CleanedBody string `json:"body"`
			UserId      string `json:"user_id"`
		}
		// Decode the JSON body
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid request body"))
			return
		}

		// Validate the chirp body length
		if len(params.Body) > 140 {
			log.Printf("Chirp body exceeds 140 characters")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Chirp body exceeds 140 characters"))
			return
		}
		// Validate the user ID is not empty
		if len(params.UserID) == 0 {
			log.Printf("User ID cannot be empty")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("User ID cannot be empty"))
			return
		}

		// Parse the user_id as UUID
		userUUID, err := uuid.Parse(params.UserID)
		if err != nil {
			log.Printf("Invalid user_id: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid user_id format"))
			return
		}
		chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   cleanupString(params.Body),
			UserID: uuid.NullUUID{UUID: userUUID, Valid: true},
		})

		if err != nil {
			log.Printf("Error inserting chirp into database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error inserting chirp into database"))
			return
		}

		// Prepare the response
		response := returnData{
			Id:          chirp.ID.String(),
			CreatedAt:   chirp.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   chirp.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			CleanedBody: chirp.Body,
			UserId:      "",
		}
		if chirp.UserID.Valid {
			response.UserId = chirp.UserID.UUID.String()
		}

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	})

	// Add a handler to except GET request to list all chirps
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type returnData struct {
			Id        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Body      string `json:"body"`
			UserId    string `json:"user_id"`
		}
		// Fetch all chirps from the database
		chirps, err := apiCfg.dbQueries.GetAllChirps(r.Context())
		if err != nil {
			log.Printf("Error fetching chirps from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error fetching chirps from database"))
			return
		}
		var response []returnData
		for _, chirp := range chirps {
			chirpData := returnData{
				Id:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Body:      chirp.Body,
				UserId:    "",
			}
			if chirp.UserID.Valid {
				chirpData.UserId = chirp.UserID.UUID.String()
			}
			response = append(response, chirpData)
		}

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	// Add a handler to except GET request to fetch a single chirp by ID
	mux.HandleFunc("GET /api/chirps/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Extract the ID from the URL
		id := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
		if len(id) == 0 {
			log.Printf("Chirp ID is required")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Chirp ID is required"))
			return
		}

		// Parse the ID as UUID
		chirpUUID, err := uuid.Parse(id)
		if err != nil {
			log.Printf("Invalid chirp ID: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid chirp ID format"))
			return
		}

		type returnData struct {
			Id        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Body      string `json:"body"`
			UserId    string `json:"user_id"`
		}

		// Fetch the chirp from the database
		chirp, err := apiCfg.dbQueries.GetChirp(r.Context(), chirpUUID)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Chirp not found: %v", err)
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Chirp not found"))
				return
			}
			log.Printf("Error fetching chirp from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error fetching chirp from database"))
			return
		}

		// Prepare the response
		response := returnData{
			Id:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Body:      chirp.Body,
			UserId:    "",
		}
		if chirp.UserID.Valid {
			response.UserId = chirp.UserID.UUID.String()
		}

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	// Add a handler to except POST request as JSON body to create a user
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
		}
		var params parameters
		var response struct {
			ID        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Email     string `json:"email"`
		}
		// Decode the JSON body
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid request body"))
			return
		}

		// Validate the email is not empty
		if len(params.Email) == 0 {
			log.Printf("Email cannot be empty")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Email cannot be empty"))
			return
		}

		// Insert the user into the database
		user, err := apiCfg.dbQueries.CreateUser(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error inserting user into database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error inserting user into database"))
			return
		}

		response.ID = user.ID.String()
		if user.CreatedAt.Valid {
			response.CreatedAt = user.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		} else {
			response.CreatedAt = ""
		}
		if user.UpdatedAt.Valid {
			response.UpdatedAt = user.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		} else {
			response.UpdatedAt = ""
		}
		response.Email = user.Email

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	})

	// Serve the static HTML file
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	// Create the server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Starting server on localhost:8080...")
	log.Fatal(server.ListenAndServe())
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Increment the fileserverHits counter
		cfg.fileserverHits.Add(1)

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func cleanupString(s string) string {
	bannedWords := []string{"kerfuffle", "sharbert", "fornax", "Kerfuffle", "Sharbert", "Fornax"}

	for _, word := range bannedWords {
		s = strings.ReplaceAll(s, word, "****")
	}

	return s
}
