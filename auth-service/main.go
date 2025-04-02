package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// JWT Secret Key
var secretKey = []byte("supersecret")

// Redis Client
var redisClient *redis.Client

// Database Connection
var db *gorm.DB

// User Model
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
}

// Claims Structure for JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Initialize Database
func initDB() {
	dsn := "host=postgres user=postgres password=postgres dbname=userservice port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
}

// Initialize Redis
func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr: "redis:6379",
		DB:   0,
	})
}

// Validate JWT Token
func validateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	// Remove "Bearer " prefix if exists
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Check in Redis cache first
	ctx := context.Background()
	if username, err := redisClient.Get(ctx, tokenString).Result(); err == nil {
		c.JSON(http.StatusOK, gin.H{"status": "valid", "user": username})
		return
	}

	// Parse JWT token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Extract username
	claims, _ := token.Claims.(*Claims)
	username := claims.Username

	// Check if user exists in the database
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Store token in Redis for faster validation
	redisClient.Set(ctx, tokenString, username, 0)

	c.JSON(http.StatusOK, gin.H{"status": "valid", "user": username})
}

// Main function
func main() {
	initDB()
	initRedis()

	router := gin.Default()
	router.GET("/validate", validateToken)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	fmt.Println("Auth Service running on port", port)
	router.Run(":" + port)
}
