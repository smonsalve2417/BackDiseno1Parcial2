package main

import (
	"fmt"
	"log"
	"net/http"
	"syscall"
)

var (
	httpAddr          = ":8080"
	mongoAddr         = GetEnv("MONGO_ADDR", "mongodb://root:example@mongodb:27017/")
	mongoDatabaseName = GetEnv("MONGO_DATABASE_NAME", "parkwise")
	JWTSecret         = GetEnv("JWTSECRET", "askjhsbdfkuhbdsfuyhasdnasdisdfiyuhb")
)

func main() {
	fmt.Println("MONGO_ADDR:", mongoAddr)
	fmt.Println("MONGO_DATABASE_NAME:", mongoDatabaseName)

	mux := http.NewServeMux()

	mongoClient, err := NewMongoDBStorage(mongoAddr, mongoDatabaseName)
	if err != nil {
		log.Fatal("Error connecting to MongoDB: ", err)
	}

	store := NewStore(mongoClient.GetDatabase().Client())
	handler := NewHandler(store)
	handler.registerRoutes(mux)

	corsMux := enableCORS(mux)

	log.Printf("Starting HTTP server at %s", httpAddr)
	if err := http.ListenAndServe(httpAddr, corsMux); err != nil {
		log.Fatal("Failed to start http server:", err)
	}
}

func GetEnv(key string, fallback string) string {
	if value, ok := syscall.Getenv(key); ok {
		return value
	}
	return fallback
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Adjust the origin as needed
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
