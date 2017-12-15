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
	"github.com/lib/pq"
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
	UserID		uint64		`json:"userID,omitempty"`
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
type ErrorHandlerMessageArray struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Messages[] Message		`json:"context,omitempty"`
}
type ErrorHandlerChannelArray struct{
	ErrorMessage string	 	`json:"message"`
	ErrorCode int 			`json:"code"`
	Channels[] Channel		`json:"context,omitempty"`
}

type Channel struct{
	ChannelID uint64				`json:"channelID,omitempty" gorm:"primary_key"`
	CreatedAt time.Time				`json:"createdAt"`
	UpdatedAt time.Time				`json:"updatedAt,omitemtpy"`
	DeletedAt *time.Time			`json:"-"`
	ChannelName string 				`json:"channelName"`
	UserID uint64					`json:"ownerID"`
	IsPrivate bool					`json:"isPrivate"`
	Password string					`json:"password,omitempty"`
	AvailableDays pq.StringArray 	`json:"availableDays" gorm:"type:varchar(10)[]"`
	StartTime time.Time				`json:"startTime"`
	EndTime time.Time				`json:"endTime"`
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
	Username string 				`json:"nickname"`
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
	if !tools.ValidateEmail(requestingUser.Username){
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage="This is not a valid email address"
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
		checkLoginError.Context.UserID = requestingUser.UserID
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

/*func GetUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var checkError ErrorHandlerArray
	tools.DB.Find(&checkError.Users)
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}*/

func CreateChannel(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	var checkError ErrorHandler
	var finalChannelInput Channel
	claims := token.Claims.(jwt.MapClaims)
	var channelInput struct{
		Channel
		Start_Time	string	`json:"startTime"`
		End_Time string		`json:"endTime"`
	}
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
	fmt.Println(channelInput.Start_Time)

	channelInput.Start_Time = "1971-01-01T" + channelInput.Start_Time + ":00+03:00"
	channelInput.End_Time = "1971-01-01T" + channelInput.End_Time + ":00+03:00"

	finalChannelInput.StartTime, _ = time.Parse(time.RFC3339, channelInput.Start_Time)
	finalChannelInput.EndTime, _ = time.Parse(time.RFC3339, channelInput.End_Time)
	fmt.Println(finalChannelInput.StartTime)
	finalChannelInput.ChannelName=channelInput.ChannelName
	finalChannelInput.UserID = uint64(claims["userID"].(float64))
	finalChannelInput.Password = channelInput.Password
	finalChannelInput.IsPrivate = channelInput.IsPrivate
	finalChannelInput.AvailableDays = channelInput.AvailableDays
	var tempChannel Channel
	if err := tools.DB.Where("channel_name = ?", finalChannelInput.ChannelName).First(&tempChannel).Error; err == nil{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorMessage="This channel name already exists"
		checkError.ErrorCode=3
		jsonResp,_ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	if err := tools.DB.Create(&finalChannelInput).Error; err!=nil{
		w.WriteHeader(http.StatusServiceUnavailable)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	var temp ChannelMembers
	temp.ChannelID = channelInput.ChannelID
	temp.UserID = uint64(claims["userID"].(float64))

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

func GetChannels(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var checkError ErrorHandlerChannelArray
	var channelMemberRequest ChannelMembers
	var chnID []ChannelMembers
	var chnl Channel
	/*if err = json.NewDecoder(r.Body).Decode(&channelMemberRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}*/
	channelMemberRequest.UserID = uint64(claims["userID"].(float64))
	//if channelMemberRequest.ChannelID <= 0{
		tx := tools.DB.Begin()
		if err := tx.Table("channel_members").Where("user_id = ?",channelMemberRequest.UserID).Find(&chnID).Error; err != nil{
			tx.Rollback()
			fmt.Println("burada mi patladin")
			w.WriteHeader(http.StatusServiceUnavailable)
			checkError.ErrorCode=3
			checkError.ErrorMessage=err.Error()
			jsonResp, _ := json.Marshal(checkError)
			fmt.Fprintf(w, string(jsonResp))
			return
		}
		for i := 0; i<len(chnID) ; i++{
			chnl.ChannelID = chnID[i].ChannelID
			if err := tx.Find(&chnl).Error; err != nil{
				tx.Rollback()
				w.WriteHeader(http.StatusServiceUnavailable)
				checkError.ErrorCode=3
				checkError.ErrorMessage=err.Error()
				jsonResp, _ := json.Marshal(checkError)
				fmt.Fprintf(w, string(jsonResp))
				return
			}
			chnl.Password = ""
			checkError.Channels = append(checkError.Channels, chnl)
		}
		tx.Commit()
		w.WriteHeader(http.StatusOK)
		checkError.ErrorCode=0
		checkError.ErrorMessage="success"
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	/*}
	w.WriteHeader(http.StatusBadRequest)
	checkError.ErrorCode = 2
	checkError.ErrorMessage = "bad request"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return*/
}

func SendMessage(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var messageInput Message
	var checkError ErrorHandler
	if err = json.NewDecoder(r.Body).Decode(&messageInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	/*

	IF STATEMENTLAR EKSİK

	*/
	messageInput.UserID = uint64(claims["userID"].(float64))

	var temp ChannelMembers
	temp.UserID = messageInput.UserID
	temp.ChannelID = messageInput.ChannelID

	tx := tools.DB.Begin()
	if err := tx.First(&temp).Error; err != nil{
		tx.Rollback()
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	var tempUser User
	if err := tx.Where("user_id =?",temp.UserID).First(&tempUser).Error; err != nil{
		tx.Rollback()
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	messageInput.Username = tempUser.Nickname
	if err := tx.Create(&messageInput).Error; err != nil{
		tx.Rollback()
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	tx.Commit()
	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}

func GetMessages(w http.ResponseWriter, r * http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var messageInput Message
	var checkError ErrorHandlerMessageArray
	var msgArray []Message
	/*

	IF STATEMENTLAR EKSİK

	*/
	if err = json.NewDecoder(r.Body).Decode(&messageInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	messageInput.UserID = uint64(claims["userID"].(float64))
	var temp ChannelMembers
	temp.UserID = messageInput.UserID
	temp.ChannelID = messageInput.ChannelID

	if err := tools.DB.First(&temp).Error; err != nil{
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if err := tools.DB.Where("channel_id = ?", messageInput.ChannelID).Find(&msgArray).Error; err!=nil{
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
	checkError.Messages = msgArray
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}

func SearchChannel(w http.ResponseWriter, r* http.Request){
	w.Header().Set("Content-Type", "application/json")
	var channelInput Channel
	var checkError ErrorHandlerChannelArray
	if err = json.NewDecoder(r.Body).Decode(&channelInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	if channelInput.ChannelID != 0 || channelInput.UserID !=0 || len(channelInput.AvailableDays) != 0 || len(channelInput.Password) != 0 || len(channelInput.ChannelName) <=0{
		checkError.ErrorCode = 2
		checkError.ErrorMessage = "BAD REQUEST"
		w.WriteHeader(http.StatusBadRequest)
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	var matchingChannels []Channel
	searchQuery := "%"+channelInput.ChannelName+"%"
	if err := tools.DB.Where("channel_name LIKE ?", searchQuery).Find(&matchingChannels).Error; err != nil{
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	checkError.Channels = matchingChannels
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}

func Profile(w http.ResponseWriter, r* http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var checkError ErrorHandlerArray
	var userRequest User
	userRequest.UserID = uint64(claims["userID"].(float64))
	if err := tools.DB.First(&userRequest).Error; err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		checkError.ErrorCode=3
		checkError.ErrorMessage=err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	checkError.Users[0] = userRequest
	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}

func ChangeProfile(w http.ResponseWriter, r* http.Request){
	w.Header().Set("Content-Type", "application/json")
	token, _ := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	claims := token.Claims.(jwt.MapClaims)
	var userInput User
	var checkError ErrorHandlerArray
	if err = json.NewDecoder(r.Body).Decode(&userInput); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	if userInput.UserID != 0 || userInput.CreatedAt != userInput.UpdatedAt {
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	var tempUser User
	if err := tools.DB.Where("user_id = ?", uint64(claims["userID"].(float64))).First(&tempUser).Error; err != nil{
		w.WriteHeader(http.StatusBadRequest)
		checkError.ErrorCode = 2
		checkError.ErrorMessage = err.Error()
		jsonResp, _ := json.Marshal(checkError)
		fmt.Fprintf(w, string(jsonResp))
		return
	}
	tempUser.Username = userInput.Username
	tempUser.PhoneNumber = userInput.PhoneNumber
	tempUser.Nickname = userInput.Nickname
	tempUser.RealName = userInput.RealName
	tempUser.RealSurname = userInput.RealSurname
	if len(userInput.Password) > 0 {
		tempUser.Password = userInput.Password
	}
	tools.DB.Save(&tempUser)
	w.WriteHeader(http.StatusOK)
	checkError.ErrorCode=0
	checkError.ErrorMessage="success"
	jsonResp, _ := json.Marshal(checkError)
	fmt.Fprintf(w, string(jsonResp))
	return
}