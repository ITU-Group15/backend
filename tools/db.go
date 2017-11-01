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
		DB, err = gorm.Open("postgres", "postgres://yhkiyjwaeptfgz:2b94be719840537f34736bd98ce9cfaf1f75e32f67b6ac2b12cbb6030483bffd@ec2-107-20-188-239.compute-1.amazonaws.com:5432/d6rhk0shpp8dnu")
	}
	if err != nil {
		log.Fatalf("Error opening database: %q", err)
	}

	//defer DB.Close()
}
