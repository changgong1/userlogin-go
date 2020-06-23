package config

import (
	"time"

	"github.com/changgong1/userlogin-go/login_service/db"
)

var AppConfig Config

type Config struct {
	Addr       string
	StreamAddr string
	DB         db.DBConfig
	ReqTimeOut time.Duration // 请求超时时间
}

func NewConfig(config Config) {
	AppConfig = config
}
