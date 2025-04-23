package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"unique;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	Role         string    `gorm:"type:ENUM('employer','employee');not null" json:"role"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

type Employee struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"uniqueIndex;not null" json:"user_id"`
	FirstName string    `gorm:"not null" json:"first_name"`
	LastName  string    `gorm:"not null" json:"last_name"`
	ResumeURL string    `json:"resume_url"`
	DOB       time.Time `gorm:"type:date" json:"date_of_birth"`
}

type Employer struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	UserID         uint   `gorm:"uniqueIndex;not null" json:"user_id"`
	CompanyName    string `gorm:"not null" json:"company_name"`
	CompanyAddress string `json:"company_address"`
	Phone          string `json:"phone"`
	WebsiteURL     string `json:"website_url"`
}

type Job struct {
	ID             uint          `gorm:"primaryKey" json:"id"`
	EmployerID     uint          `gorm:"not null;foreignKey:EmployerID" json:"employer_id"`
	Title          string        `gorm:"not null" json:"title"`
	Description    string        `json:"description"`
	Location       string        `json:"location"`
	EmploymentType string        `gorm:"type:ENUM('full-time','part-time','contract');not null" json:"employment_type"`
	SalaryMin      float64       `json:"salary_min"`
	SalaryMax      float64       `json:"salary_max"`
	PostedAt       time.Time     `gorm:"autoCreateTime" json:"posted_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	Applications   []Application `gorm:"foreignKey:JobID" json:"applications,omitempty"`
}

type Application struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	JobID       uint      `gorm:"not null;foreignKey:JobID" json:"job_id"`
	EmployeeID  uint      `gorm:"not null;foreignKey:EmployeeID" json:"employee_id"`
	AppliedAt   time.Time `gorm:"autoCreateTime" json:"applied_at"`
	Status      string    `gorm:"type:ENUM('pending','accepted','rejected');not null" json:"status"`
	CoverLetter string    `json:"cover_letter"`
}

var jwtSecret = []byte(getEnv("JWT_SECRET", "supersecretkey"))
var db *gorm.DB

func main() {

	dsn := getEnv("DB_DSN", "slime:warui_slime#6979@tcp(127.0.0.1:3306)/jobportal?charset=utf8mb4&parseTime=True&loc=Local")
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	db.AutoMigrate(&User{}, &Employee{}, &Employer{}, &Job{}, &Application{})

	r := gin.Default()

	r.Use(corsMiddleware())

	r.POST("/signup", signupHandler)
	r.POST("/login", loginHandler)
	r.GET("/health", healthHandler)

	auth := r.Group("/")
	auth.Use(authMiddleware())
	auth.GET("/profile", profileHandler)

	emp := auth.Group("/employee")
	emp.Use(roleMiddleware("employee"))
	emp.GET("/jobs", listJobsForEmployee)
	emp.POST("/applications", applyJobHandler)
	emp.GET("/applications", listApplicationsForEmployee)

	// Employer routes
	er := auth.Group("/employer")
	er.Use(roleMiddleware("employer"))
	er.POST("/jobs", createJobHandler)
	er.GET("/jobs", listJobsForEmployer)
	er.GET("/applications", listApplicationsForEmployer)

	log.Println("Server started on :8080")
	r.Run(":8080")
}

func signupHandler(c *gin.Context) {
	var input struct{ Email, Password, Role string }
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pw, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	user := User{Email: input.Email, PasswordHash: string(pw), Role: input.Role}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email, "role": user.Role})
}

func loginHandler(c *gin.Context) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	})

	tkn, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create token"})
		return
	}

	c.SetCookie("jwt", tkn, 3600*24, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "logged in",
		"role":    user.Role,
	})
}

func profileHandler(c *gin.Context) {

	userID := c.GetUint("user_id")
	role := c.GetString("role")

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch user"})
		return
	}

	resp := gin.H{
		"id":    user.ID,
		"email": user.Email,
		"role":  role,
	}

	switch role {
	case "employee":
		var emp Employee
		if err := db.Where("user_id = ?", userID).First(&emp).Error; err == nil {
			resp["profile"] = gin.H{
				"first_name": emp.FirstName,
				"last_name":  emp.LastName,
				"resume_url": emp.ResumeURL,
			}
		}
	case "employer":
		var er Employer
		if err := db.Where("user_id = ?", userID).First(&er).Error; err == nil {
			resp["profile"] = gin.H{
				"company_name":    er.CompanyName,
				"company_address": er.CompanyAddress,
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func listJobsForEmployee(c *gin.Context) {
	var jobs []Job

	if err := db.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch jobs", "details": err.Error()})
		return
	}

	if len(jobs) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "No available jobs"})
		return
	}

	c.JSON(http.StatusOK, jobs)
}

func applyJobHandler(c *gin.Context) {
	var input struct {
		JobID       uint   `json:"job_id"`
		CoverLetter string `json:"cover_letter"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var job Job
	if err := db.First(&job, input.JobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	empID := c.GetUint("user_id")
	app := Application{
		JobID:       input.JobID,
		EmployeeID:  empID,
		Status:      "pending",
		CoverLetter: input.CoverLetter,
	}

	if err := db.Create(&app).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, app)
}

func listApplicationsForEmployee(c *gin.Context) {
	empID := c.GetUint("user_id")
	var apps []Application
	db.Where("employee_id = ?", empID).Find(&apps)
	c.JSON(http.StatusOK, apps)
}

func createJobHandler(c *gin.Context) {
	var job Job
	if err := c.ShouldBindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	emID := c.GetUint("user_id")
	job.EmployerID = emID
	job.PostedAt = time.Now()
	if err := db.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, job)
}

func listJobsForEmployer(c *gin.Context) {
	emID := c.GetUint("user_id")
	var jobs []Job
	db.Preload("Applications").Where("employer_id = ?", emID).Find(&jobs)
	c.JSON(http.StatusOK, jobs)
}

func listApplicationsForEmployer(c *gin.Context) {
	emID := c.GetUint("user_id")
	var apps []Application
	db.Joins("JOIN jobs ON jobs.id = applications.job_id").Where("jobs.employer_id = ?", emID).Find(&apps)
	c.JSON(http.StatusOK, apps)
}

// Middleware

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", getEnv("FRONTEND_ORIGIN", "http://localhost:3000"))
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization")
		c.Header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tkn, err := c.Cookie("jwt")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		parsed, err := jwt.Parse(tkn, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !parsed.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		claims := parsed.Claims.(jwt.MapClaims)
		c.Set("user_id", uint(claims["sub"].(float64)))
		c.Set("role", claims["role"].(string))
		c.Next()
	}
}

func roleMiddleware(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") != role {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
