package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/changgong1/userlogin-go/login_service/cache"
	"github.com/changgong1/userlogin-go/login_service/config"
	"github.com/changgong1/userlogin-go/login_service/db"
	"github.com/changgong1/userlogin-go/login_service/service"
	"github.com/cihub/seelog"
	"github.com/jinzhu/configor"
)

func main() {
	err := InitLog()
	if err != nil {
		return
	}
	// 启动服务
	service.Start()

	InitSignal()
}

func InitLog() error {
	logger, err := seelog.LoggerFromConfigAsFile("./login_service/config/logger.xml")
	if err != nil {
		seelog.Errorf("init logger from %s error: %v", "./login_serviceconfig/logger.xml", err)
		return err
	} else {
		if err := seelog.ReplaceLogger(logger); err != nil {
			seelog.Errorf("replace logger error %v", err)
			return err
		}
	}
	defer seelog.Flush()
	seelog.Info("log success")

	var appConfig config.Config
	configFlag := flag.String("config", "./login_service/config/config.yml", "configuration file")
	if err := configor.Load(&appConfig, *configFlag); err != nil {
		seelog.Criticalf("load config error: %v", err)
		return err
	}
	config.NewConfig(appConfig)

	// initDb
	err = db.NewBaseDabase(&config.AppConfig.DB)
	if err != nil {
		return err
	}

	// initCache
	err = cache.NewRedisClient()
	if err != nil {
		return err
	}
	return nil
}

// InitSignal register signals handler.
func InitSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	for {
		s := <-c
		seelog.Infof("application[%v] get a signal %v", "", s.String())
		switch s {
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
			return
		case syscall.SIGHUP:
			continue
		default:
			return
		}
	}
}
