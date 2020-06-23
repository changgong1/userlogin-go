package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/changgong1/userlogin-go/login_client/config"
	"github.com/changgong1/userlogin-go/login_client/src"
	"github.com/cihub/seelog"
	"github.com/jinzhu/configor"
)

var userInfo src.UserLoginModel

func main() {
	InitLog()

	fmt.Println("************ userlogin ***************")
	fmt.Println("enter 'Register' to register account")
	fmt.Println("enter 'Login' to Login account")
	fmt.Println("enter 'quit' to Logout account")
	fmt.Println("enter 'getu' to get user login info")
	fmt.Println("**************************************")
	userInfo.InitField()
	userInfo.UserAction()

}

func InitLog() {
	logger, err := seelog.LoggerFromConfigAsFile("./login_client/config/logger.xml")
	if err != nil {
		seelog.Errorf("init logger from %s error: %v", "./login_client/config/logger.xml", err)
	} else {
		if err := seelog.ReplaceLogger(logger); err != nil {
			seelog.Errorf("replace logger error %v", err)
		}
	}
	defer seelog.Flush()
	seelog.Info("log success")

	var appConfig config.Config
	configFlag := flag.String("config", "./login_client/config/config.yml", "configuration file")
	if err := configor.Load(&appConfig, *configFlag); err != nil {
		seelog.Criticalf("load config error: %v", err)
		os.Exit(1)
	}
	config.NewConfig(appConfig)
}
