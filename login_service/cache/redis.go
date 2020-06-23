package cache

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/changgong1/userlogin-go/login_service/config"
	"github.com/cihub/seelog"
	"github.com/go-redis/redis"
)

const TokenMap = "redis_user_token_map"

var cacheClient *redis.Client

func NewRedisClient() error {
	seelog.Info("start cache")
	cacheClient = redis.NewClient(&redis.Options{
		Addr:     config.AppConfig.RedisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	pong, err := cacheClient.Ping().Result()
	if err != nil {
		seelog.Error(err)
		return err
	}
	seelog.Info(pong)
	return nil
}

type TokenInfo struct {
	Token      string `json:"token"`
	UserId     string //`json:"user_id"`
	DeviceId   string //`json:"device_id"`
	LoginTime  int64  //`json:"login_time"`
	ExpireTime int64  //`json:"expire_time"`
}

func (t *TokenInfo) CheckTokenFeild() error {
	if t.Token == "" || t.UserId == "" {
		return errors.New("token info aren't enough")
	}
	return nil
}

func AddToken(tokenInfo *TokenInfo) error {
	err := tokenInfo.CheckTokenFeild()
	if err != nil {
		return err
	}
	nowTime := time.Now().Unix()
	tokenInfo.ExpireTime = nowTime + config.AppConfig.TokenExpireTime
	value, err := json.Marshal(tokenInfo)
	if err != nil {
		return err
	}
	_, err = cacheClient.HSet(TokenMap, tokenInfo.UserId, string(value)).Result()
	if err != nil {
		return err
	}
	return nil
}

func GetToken(userId string) (*TokenInfo, error) {
	vByte, err := cacheClient.HGet(TokenMap, userId).Bytes()
	if err != nil {
		seelog.Errorf("get token failed, err%v", err)
		return nil, err
	}
	tokenInfo := &TokenInfo{}
	err = json.Unmarshal(vByte, tokenInfo)
	if err != nil {
		seelog.Errorf("get token failed, err%v", err)
		return nil, err
	}
	return tokenInfo, nil
}
