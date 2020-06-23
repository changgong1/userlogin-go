package config

import (
	"github.com/changgong1/userlogin-go/login_service/db"
)

var AppConfig Config

type Config struct {
	Addr string
	DB   db.DBConfig
}

func NewConfig(config Config) {
	AppConfig = config
}
