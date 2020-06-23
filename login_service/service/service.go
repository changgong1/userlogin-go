package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	userlogin "github.com/changgong1/userlogin-go/login_guide"
	"github.com/changgong1/userlogin-go/login_service/cache"
	"github.com/changgong1/userlogin-go/login_service/config"
	"github.com/changgong1/userlogin-go/login_service/db"
	"github.com/changgong1/userlogin-go/login_service/utils"
	"github.com/cihub/seelog"
	"google.golang.org/grpc"
)

const LoginSuccess = 0
const LoginFailed = 1

// server is used to implement helloworld.GreeterServer.
type server struct {
	userlogin.UnimplementedGreeterServer
}

func (s *server) UserRegister(ctx context.Context, in *userlogin.LoginRequest) (*userlogin.TokenReply, error) {
	seelog.Infof("Received: %v", in)
	userInfo, err := db.GetUserInfoByUserId(in.UserId)
	if err != nil || userInfo != nil {
		if userInfo != nil {
			err = errors.New("user is registered")
		}
		return nil, err
	}
	userInfo = &db.UserInfo{}
	userInfo.UserId = in.UserId
	userInfo.PasswordFactor = utils.GetRandomString(config.AppConfig.FactorLangth)
	userInfo.PasswordChar = utils.HmacSha256(in.Password+userInfo.PasswordFactor, config.AppConfig.PwdSecret)

	effect, err := userInfo.AddUserInfo()
	if err != nil || effect != 1 {
		return nil, err
	}
	token, err := login(in)
	if err != nil {
		return nil, err
	}

	return &userlogin.TokenReply{Token: token}, nil
}

func (s *server) UserLogin(ctx context.Context, in *userlogin.LoginRequest) (*userlogin.TokenReply, error) {
	seelog.Infof("Received: %v", in)
	userInfo, err := db.GetUserInfoByUserId(in.UserId)
	if err != nil || userInfo == nil {
		return nil, errors.New("login failed")
	}
	if !chekcPassword(userInfo.PasswordChar, userInfo.PasswordFactor, in.Password) {
		return nil, errors.New("password is invalid")
	}
	token, err := login(in)
	if err != nil {
		return nil, errors.New("login failed")
	}
	return &userlogin.TokenReply{Token: token}, nil
}
func chekcPassword(passworChar, passwordFactor, password string) bool {
	tmpChar := utils.HmacSha256(password+passwordFactor, config.AppConfig.PwdSecret)

	return tmpChar == passworChar
}

func login(in *userlogin.LoginRequest) (string, error) {
	now := time.Now().Unix()
	tokenInfo := cache.TokenInfo{
		UserId:    in.UserId,
		DeviceId:  in.DeviceId,
		LoginTime: now,
	}
	tokenText, err := json.Marshal(tokenInfo)
	if err != nil {
		seelog.Errorf("marshal failed, err:%v", err)
		return "", err
	}
	tokenOne := utils.HmacSha256Base64(string(tokenText), config.AppConfig.TokenSecret)
	tokenTwo, err := utils.AesEncrypt(in.UserId, config.AppConfig.TokenSecret)
	if err != nil {
		seelog.Errorf("AesEncrypt failed, err:%v", err)
		return "", err
	}
	tokenInfo.Token = tokenOne + "." + tokenTwo

	err = cache.UpdateToken(&tokenInfo)
	if err != nil {
		seelog.Errorf("add failed, err:%v", err)
		return "", err
	}
	return tokenInfo.Token, nil
}
func parseToken(in *userlogin.TokenCheckRequest) (string, error) {
	tokenList := strings.Split(in.Token, ".")
	if len(tokenList) != 2 {
		return "", errors.New("token is invalid")
	}
	secretText := tokenList[1]
	userId, err := utils.AesDncrypt(secretText, config.AppConfig.TokenSecret)
	if err != nil {
		return "", err
	}
	seelog.Info(userId)
	return userId, nil
}
func (s *server) TokenCheck(ctx context.Context, in *userlogin.TokenCheckRequest) (*userlogin.TokenCheckReply, error) {
	var flag int32 = LoginFailed
	userId, err := parseToken(in)
	if err != nil {
		return nil, err
	}
	tokenTmp, err := cache.GetToken(userId)
	if err != nil {
		return nil, err
	}
	if tokenTmp.Token == in.Token && tokenTmp.ExpireTime > time.Now().Unix() {
		flag = LoginSuccess
	}
	err = cache.UpdateToken(tokenTmp)
	if err != nil {
		seelog.Errorf("updage failed, err:%v", err)
		return nil, err
	}
	return &userlogin.TokenCheckReply{Flag: flag}, nil
}

func Start() {
	seelog.Infof("login_service start")

	lis, err := net.Listen("tcp", config.AppConfig.Addr)
	if err != nil {
		seelog.Errorf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	userlogin.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		seelog.Errorf("failed to serve: %v", err)
	}
}
