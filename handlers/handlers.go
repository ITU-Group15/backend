package handlers

import (
	"crypto/rsa"
	"time"
	"io/ioutil"
	"channelx/tools"
	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"

	"net/http"
	"encoding/json"
	"fmt"
	"log"
)

const (
	privKeyPath = "orangenotes/demo"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "orangenotes/demo.pub"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	err	error
)


type ContextStruct struct{
	JwtToken	string 		`json:"jwtToken"`
}

type LoginErrorHandler struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Context ContextStruct	`json:"context,omitempty"`
}

type ErrorHandlerArray struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Users[] User	`json:"context,omitempty"`
}


type User struct {
	UserID uint64					`json:"userID,omitempty" gorm:"primary_key"`
	//gorm.Model
	CreatedAt time.Time				`json:"createdAt"`
	UpdatedAt time.Time				`json:"updatedAt,omitemtpy"`
	DeletedAt *time.Time			`json:"-"`
	Username string					`json:"username,omitempty"`
	Password string 				`json:"password,omitempty"`
	PhoneNumber string				`json:"phone,omitempty"`
	RealName	string				`json:"realname,omitempty"`
	RealSurname	string				`json:"realsurname,omitempty"`
}

func init() {
	privateByte, _ := ioutil.ReadFile("demo.rsa")
	publicByte, _ := ioutil.ReadFile("demo.rsa.pub")
	privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(privateByte)
	publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(publicByte)
	tools.DB.CreateTable(&User{})
}

func (User) TableName() string{
	return "users"
}


func RegisterFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var (
		requestingUser User
		checkError LoginErrorHandler
	)
	if err = json.NewDecoder(r.Body).Decode(&requestingUser); err != nil{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode=2
		checkError.ErrorMessage=err.Error()
		jsonResp,_ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if requestingUser.UserID != 0{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage="invalid json"
		checkError.ErrorCode=2
		jsonResp,_ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if len(requestingUser.Username) <= 0 || len(requestingUser.Password) <= 0{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage="Username or Password cannot be empty"
		checkError.ErrorCode=2
		jsonResp,_ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if err := tools.DB.Where("username = ?", requestingUser.Username).First(&requestingUser).Error; err == nil{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage="This username already exists"
		checkError.ErrorCode=3
		jsonResp,_ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	tx := tools.DB.Begin().Table("users")
	if err := tx.Create(&requestingUser).Error; err != nil{
		tx.Rollback()
		w.WriteHeader(http.StatusServiceUnavailable)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	tx.Commit()
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
}

func LoginFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var (
		userInput      User
		userToken      uint64
		checkError     LoginErrorHandler
		requestingUser User
	)
	if err = json.NewDecoder(r.Body).Decode(&userInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if len(userInput.Username) <= 0 || len(userInput.Password) <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage = "Username or Password cannot be empty"
		checkError.ErrorCode = 2
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if err := tools.DB.Where("username = ?", userInput.Username).First(&requestingUser).Error; err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println(requestingUser.Username)
		log.Println(userInput.Username)
		checkError.ErrorMessage = "This username does not exists"
		checkError.ErrorCode = 3
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	if requestingUser.Username == userInput.Username && userInput.Password == requestingUser.Password {
		var checkLoginError LoginErrorHandler
		userToken = requestingUser.UserID
		token := jwt.New(jwt.GetSigningMethod("RS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["userID"] = userToken
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
		tokenString, _ := token.SignedString(privateKey)
		checkLoginError.ErrorCode = 0
		checkLoginError.ErrorMessage = "success"
		checkLoginError.Context.JwtToken = tokenString
		jsonResp, _ := json.Marshal(checkLoginError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	checkError.ErrorMessage = "Username and Password do not match"
	checkError.ErrorCode = 3
	w.WriteHeader(http.StatusBadRequest)
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var checkError ErrorHandlerArray
	tools.DB.Find(&checkError.Users)
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}
