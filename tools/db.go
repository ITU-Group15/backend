package tools

import (
	"os"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"log"
)
var 	DB	*gorm.DB
var 	err	error

func init(){
	port := os.Getenv("PORT")
	if port == "8080"{	//LOCALHOST DB
		DB, err = gorm.Open("postgres", "user=postgres password=batu67 dbname=channelx sslmode=disable")
	}else{				//HEROKU DB
		DB, err = gorm.Open("postgres", "postgres://wqskvaosobuomo:fd4b6b72280f4e83d8c88b979ecee72367fac75e99863452b4749de74cfe9e00@ec2-54-247-124-9.eu-west-1.compute.amazonaws.com:5432/d8dbg22v3r0lku")
	}
	if err != nil {
		log.Fatalf("Error opening database: %q", err)
	}

	//defer DB.Close()
}
