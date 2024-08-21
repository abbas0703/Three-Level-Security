package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	templates = template.Must(template.ParseFiles(
		"tls/login.html",
		"tls/register.html",
	))
	client *mongo.Client
)

type User struct {
	Username string `bson:"username"`
	Password string `bson:"password"`
}

func main() {
	// Load environment variables from .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// MongoDB URI from environment variable
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MongoDB URI not found in environment variables")
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// Ensure connection is established
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB Atlas!")
	fmt.Println("Server is running on http://localhost:8080")

	// Seed the random generator once
	rand.Seed(time.Now().UnixNano())

	// Route handlers
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/main", mainHandler)

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// hashPassword generates a SHA-256 hash for the given password
func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// generateCaptchaCode creates a random 6-digit CAPTCHA code
func generateCaptchaCode() string {
	code := rand.Intn(999999)
	return fmt.Sprintf("%06d", code)
}

// mainHandler serves the main page after successful login
func mainHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the main page!")
}

// setCookie sets a cookie with the CAPTCHA code
func setCaptchaCookie(w http.ResponseWriter, captchaCode string) {
	http.SetCookie(w, &http.Cookie{
		Name:    "captcha",
		Value:   captchaCode,
		Expires: time.Now().Add(5 * time.Minute), // Cookie valid for 5 minutes
	})
}

// getCaptchaCookie retrieves the CAPTCHA code from the cookie
func getCaptchaCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("captcha")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// registerHandler handles the registration of new users
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := hashPassword(r.FormValue("password"))
		captchaInput := r.FormValue("captcha")

		// Validate CAPTCHA
		storedCaptcha, err := getCaptchaCookie(r)
		if err != nil || captchaInput != storedCaptcha {
			http.Error(w, "Invalid CAPTCHA", http.StatusUnauthorized)
			return
		}

		// Check if username already exists
		collection := client.Database("testdb").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var existingUser User
		err = collection.FindOne(ctx, bson.M{"username": username}).Decode(&existingUser)
		if err == nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		// Insert the new user into the database
		user := User{
			Username: username,
			Password: password,
		}

		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		// Clear CAPTCHA cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "captcha",
			Value:   "",
			Expires: time.Now().Add(-time.Hour), // Set cookie to expire in the past
		})

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	captchaCode := generateCaptchaCode()
	setCaptchaCookie(w, captchaCode)
	data := map[string]string{
		"Captcha": captchaCode,
	}
	if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// loginHandler handles user login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := hashPassword(r.FormValue("password"))
		captchaInput := r.FormValue("captcha")

		// Validate CAPTCHA
		storedCaptcha, err := getCaptchaCookie(r)
		if err != nil || captchaInput != storedCaptcha {
			http.Error(w, "Invalid CAPTCHA", http.StatusUnauthorized)
			return
		}

		// Find user in the database
		collection := client.Database("testdb").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var user User
		err = collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Check password
		if user.Password != password {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Clear CAPTCHA cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "captcha",
			Value:   "",
			Expires: time.Now().Add(-time.Hour), // Set cookie to expire in the past
		})

		http.Redirect(w, r, "/main", http.StatusSeeOther)
		return
	}

	captchaCode := generateCaptchaCode()
	setCaptchaCookie(w, captchaCode)
	data := map[string]string{
		"Captcha": captchaCode,
	}
	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}
