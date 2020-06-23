package config

import (
	"github.com/changgong1/userlogin-go/login_service/db"
)

var AppConfig Config

type Config struct {
	Addr            string
	DB              db.DBConfig
	PwdSecret       string
	TokenSecret     string
	TokenExpireTime int64
	FactorLangth    int
	RedisAddr       string
}

func NewConfig(config Config) {
	AppConfig = config
}
