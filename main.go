package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/Kobiee88/chirpy/internal/database"

	"github.com/Kobiee88/chirpy/internal/auth"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	secretKey      string
	polkaKey       string
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
	apiCfg.secretKey = os.Getenv("SECRET_KEY")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")

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
		// Validate user token
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error extracting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid token"))
			return
		}
		userId, err := auth.ValidateJWT(tokenString, apiCfg.secretKey)
		if err != nil {
			log.Printf("Error validating JWT token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: invalid token"))
			return
		}

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
		err = json.NewDecoder(r.Body).Decode(&params)
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
		if len(userId) == 0 {
			log.Printf("User ID cannot be empty")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("User ID cannot be empty"))
			return
		}

		chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   cleanupString(params.Body),
			UserID: uuid.NullUUID{UUID: userId, Valid: true},
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
		optionalParam := r.URL.Query().Get("author_id")
		sortingParam := r.URL.Query().Get("sort")

		type returnData struct {
			Id        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Body      string `json:"body"`
			UserId    string `json:"user_id"`
		}

		var chirps []database.Chirp

		if len(optionalParam) > 0 {
			// Fetch chirps by specific user from the database
			authorUUID, err := uuid.Parse(optionalParam)
			if err != nil {
				log.Printf("Error parsing author_id: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid author_id format"))
				return
			}
			chirps, err = apiCfg.dbQueries.GetChirpsByUser(r.Context(), uuid.NullUUID{UUID: authorUUID, Valid: true})
			if err != nil {
				log.Printf("Error fetching chirps from database: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error fetching chirps from database"))
				return
			}
		} else {
			// Fetch all chirps from the database
			chirps, err = apiCfg.dbQueries.GetAllChirps(r.Context())
			if err != nil {
				log.Printf("Error fetching chirps from database: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error fetching chirps from database"))
				return
			}
		}

		if strings.ToLower(sortingParam) == "desc" {
			sort.Slice(chirps, func(i, j int) bool {
				return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
			})
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
			Password string `json:"password"`
			Email    string `json:"email"`
		}
		var params parameters
		var response struct {
			ID          string `json:"id"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
			Email       string `json:"email"`
			IsChirpyRed bool   `json:"is_chirpy_red"`
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

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error processing password"))
			return
		}

		// Insert the user into the database
		user, err := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		})
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
		response.IsChirpyRed = user.IsChirpyRed

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

	// Add a handler to except POST request as JSON body to login a user
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}
		var params parameters
		var response struct {
			ID           string `json:"id"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
			Email        string `json:"email"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
			IsChirpyRed  bool   `json:"is_chirpy_red"`
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

		// Fetch the user from the database by email
		user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("User not found: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Invalid email or password"))
				return
			}
			log.Printf("Error fetching user from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error fetching user from database"))
			return
		}

		// Compare the provided password with the stored hashed password
		match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil || !match {
			log.Printf("Invalid password for user: %s", params.Email)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid email or password"))
			return
		}

		// Generate a JWT token for the user
		expiresIn := int64(3600) // Default to 1 hour
		token, err := auth.MakeJWT(user.ID, apiCfg.secretKey, time.Duration(expiresIn)*time.Second)
		if err != nil {
			log.Printf("Error generating JWT token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error generating token"))
			return
		}

		// Generate a refresh token
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			log.Printf("Error generating refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error generating refresh token"))
			return
		}
		response.RefreshToken = refreshToken

		// Save the refresh token to the database
		_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     refreshToken,
			UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
			ExpiresAt: sql.NullTime{Time: time.Now().Add(60 * 24 * time.Hour), Valid: true},
			CreatedAt: time.Now(),
		})
		if err != nil {
			log.Printf("Error saving refresh token to database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error saving refresh token to database"))
			return
		}

		response.Token = token

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
		response.IsChirpyRed = user.IsChirpyRed

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	// Create Endpoint to Refresh Token
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error extracting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid token"))
			return
		}
		userId, err := apiCfg.dbQueries.GetUserIdFromRefreshToken(r.Context(), tokenString)
		if err != nil {
			log.Printf("Error fetching user from refresh token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: invalid refresh token"))
			return
		}

		// Generate a new JWT token for the user
		expiresIn := int64(3600) // Default to 1 hour
		token, err := auth.MakeJWT(userId, apiCfg.secretKey, time.Duration(expiresIn)*time.Second)
		if err != nil {
			log.Printf("Error generating JWT token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error generating token"))
			return
		}

		// Respond with the new token
		response := map[string]interface{}{
			"token": token,
		}
		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error extracting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid token"))
			return
		}

		err = apiCfg.dbQueries.RevokeRefreshToken(r.Context(), tokenString)
		if err != nil {
			log.Printf("Error revoking refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error revoking refresh token"))
			return
		}

		// Respond with success
		w.WriteHeader(http.StatusNoContent)
	})

	// Update user information
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		// Validate user token
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error extracting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid token"))
			return
		}
		userId, err := auth.ValidateJWT(tokenString, apiCfg.secretKey)
		if err != nil {
			log.Printf("Error validating JWT token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: invalid token"))
			return
		}

		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		var params parameters

		var response struct {
			ID          string `json:"id"`
			CreatedAt   string `json:"created_at"`
			UpdatedAt   string `json:"updated_at"`
			Email       string `json:"email"`
			IsChirpyRed bool   `json:"is_chirpy_red"`
		}

		// Decode the JSON body
		err = json.NewDecoder(r.Body).Decode(&params)
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

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error processing password"))
			return
		}

		// Update the user in the database
		_, err = apiCfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
			ID:             userId,
			Email:          params.Email,
			HashedPassword: hashedPassword,
		})
		if err != nil {
			log.Printf("Error updating user in database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error updating user in database"))
			return
		}

		// Fetch the updated user from the database
		user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error fetching user from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error fetching user from database"))
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
		response.IsChirpyRed = user.IsChirpyRed

		dat, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(dat)
		w.WriteHeader(http.StatusOK)
	})

	// Delete a chirp by ID
	mux.HandleFunc("DELETE /api/chirps/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Validate user token
		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error extracting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid token"))
			return
		}
		userId, err := auth.ValidateJWT(tokenString, apiCfg.secretKey)
		if err != nil {
			log.Printf("Error validating JWT token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: invalid token"))
			return
		}

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

		// Check if chirp belongs to the user
		chirp, err := apiCfg.dbQueries.GetChirp(r.Context(), chirpUUID)
		if err != nil {
			log.Printf("Error fetching chirp from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error fetching chirp from database"))
			return
		}
		if !chirp.UserID.Valid || chirp.UserID.UUID != userId {
			log.Printf("User %s is not authorized to delete chirp %s", userId, chirp.ID)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden: you do not own this chirp"))
			return
		}

		// Call the delete chirp function
		err = apiCfg.dbQueries.DeleteChirp(r.Context(), chirpUUID)
		if err != nil {
			log.Printf("Error deleting chirp from database: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error deleting chirp from database"))
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	// Upgrade User to Chirpy Red
	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		// Validate Polka key
		polkaKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			log.Printf("Error extracting API key: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: missing or invalid API key"))
			return
		}
		if polkaKey != apiCfg.polkaKey {
			log.Printf("Invalid API key: %s", polkaKey)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized: invalid API key"))
			return
		}

		type parameters struct {
			Event string `json:"event"`
			Data  struct {
				UserId string `json:"user_id"`
			} `json:"data"`
		}
		var params parameters

		// Decode the JSON body
		err = json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid request body"))
			return
		}
		if params.Event != "user.upgraded" {
			log.Printf("Ignoring non-upgrade event: %s", params.Event)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Upgrade the user in the database
		userUUID, err := uuid.Parse(params.Data.UserId)
		if err != nil {
			log.Printf("Invalid user_id format: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid user_id format"))
			return
		}
		_, err = apiCfg.dbQueries.UpgradeUser(r.Context(), userUUID)
		if err != nil {
			log.Printf("Error upgrading user: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Respond with 204 No Content
		w.WriteHeader(http.StatusNoContent)
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
