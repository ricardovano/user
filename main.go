package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtKey = []byte("secret-key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

func CreateToken(username string) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	users[user.Username] = user.Password
	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	password, ok := users[user.Username]
	if !ok || password != user.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := CreateToken(user.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write([]byte(token))
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Welcome to the protected area!"))
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/protected", ProtectedHandler).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}
