package handlers

import (
	"fmt"
	"net/http"
	"log"
	"encoding/json"
	"channelx/tools"
	_ "github.com/lib/pq"
	//_ "github.com/jinzhu/gorm/dialects/postgres"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"github.com/dgrijalva/jwt-go/request"
	"crypto/rsa"
	"time"
	"github.com/jinzhu/gorm"
)

const (
	privKeyPath = "channelx/demo"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "channelx/demo.pub"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	err	error
)


type ContextStruct struct{
	JwtToken	string 		`json:"jwtToken,omitempty"`
}

type ErrorHandler struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Context ContextStruct	`json:"context,omitempty"`
}

type ErrorHandlerArray struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Users[] User			`json:"context,omitempty"`
}

type Channel struct{
	ChannelID uint64				`json:"channelID,omitempty" gorm:"primary_key"`
	CreatedAt time.Time				`json:"createdAt"`
	UpdatedAt time.Time				`json:"updatedAt,omitemtpy"`
	DeletedAt *time.Time			`json:"-"`
	ChannelName string 				`json:"channelName"`
	UserID uint64					`json:"ownerID"`
	IsPrivate bool					`json:"isPrivate"`
	Password string					`json:"-"`
}

type User struct {
	UserID uint64					`json:"userID,omitempty" gorm:"primary_key"`
	CreatedAt time.Time				`json:"createdAt"`
	UpdatedAt time.Time				`json:"updatedAt,omitemtpy"`
	DeletedAt *time.Time			`json:"-"`
	Username string					`json:"username,omitempty"`
	Password string 				`json:"password,omitempty"`
	PhoneNumber string				`json:"phone,omitempty"`
	RealName	string				`json:"realname,omitempty"`
	RealSurname	string				`json:"realsurname,omitempty"`
	Nickname string					`json:"nickname,omitempty"`
}

type ChannelMembers struct {
	UserID uint64					`gorm:"primary_key"`
	ChannelID uint64				`gorm:"primary_key"`
}

type Message struct{
	gorm.Model
	ChannelID uint64				`json:"channelID"`
	UserID uint64					`json:"userID"`
	Message string					`json:"message"`
}


func init() {
	privateByte, _ := ioutil.ReadFile("demo.rsa")
	publicByte, _ := ioutil.ReadFile("demo.rsa.pub")
	privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(privateByte)
	publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(publicByte)
	tools.DB.CreateTable(&User{})
	tools.DB.CreateTable(&Channel{})
	tools.DB.CreateTable(&Message{})
	tools.DB.CreateTable(&ChannelMembers{})
}

func (User) TableName() string{
	return "users"
}

func (ChannelMembers) TableName() string{
	return "channel_members"
}

func AuthMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	w.Header().Set("Content-Type", "application/json")
	var checkError ErrorHandler
	token, err := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err == nil && token.Valid {
		next(w, r)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorMessage="Token Failure"
		checkError.ErrorCode = 5
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprint(w, string(jsonResp))
	}
}

func RegisterFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var (
		requestingUser User
		checkError     ErrorHandler
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
		checkError     ErrorHandler
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
		var checkLoginError ErrorHandler
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

func CreateChannel(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	var checkError ErrorHandler
	claims := token.Claims.(jwt.MapClaims)
	var channelInput Channel
	if err = json.NewDecoder(r.Body).Decode(&channelInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if channelInput.ChannelID != 0 || len(channelInput.ChannelName) <= 0{
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorMessage = "missing input"
		checkError.ErrorCode = 2
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if channelInput.IsPrivate != true{
		channelInput.IsPrivate = false
	}
	if channelInput.IsPrivate == true && len(channelInput.Password) <= 0{
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorMessage = "password cannot be empty on private channels"
		checkError.ErrorCode = 2
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if err := tools.DB.Create(&channelInput).Error; err!=nil{
		w.WriteHeader(http.StatusServiceUnavailable)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	var temp ChannelMembers
	temp.ChannelID = channelInput.ChannelID
	temp.UserID = channelInput.UserID
	
	if err := tools.DB.Create(&temp).Error; err!=nil{
		w.WriteHeader(http.StatusServiceUnavailable)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}

func JoinChannel(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var checkError ErrorHandler
	var channelInput Channel
	if err = json.NewDecoder(r.Body).Decode(&channelInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if channelInput.ChannelID <= 0{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage = "ChannelID required"
		checkError.ErrorCode = 2
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if len(channelInput.ChannelName) > 0 || channelInput.UserID > 0{
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorMessage = "Unauthorized request"
		checkError.ErrorCode = 2
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	temp := ChannelMembers{}
	temp.UserID = uint64(claims["userID"].(float64))
	temp.ChannelID = channelInput.ChannelID

	if err := tools.DB.Create(&temp).Error; err != nil{
		w.WriteHeader(http.StatusServiceUnavailable)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}
