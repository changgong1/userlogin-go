package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// 用户注册
func (s *server) UserRegister(ctx context.Context, in *userlogin.LoginRequest) (*userlogin.TokenReply, error) {
	seelog.Infof("Received: %v", in)
	// 检查用户是否注册过
	userInfo, err := db.GetUserInfoByUserId(in.UserId)
	if err != nil || userInfo != nil {
		if userInfo != nil {
			err = errors.New("user is registered")
		}
		return nil, err
	}
	userInfo = &db.UserInfo{}
	userInfo.UserId = in.UserId
	userInfo.PasswordChar, err = utils.DjangoEncode(in.Password, "", config.AppConfig.DjangoIterations)
	if err != nil {
		return nil, err
	}

	// 保存用户信息：用户ID，密码算子（盐），密码检查符。
	effect, err := userInfo.AddUserInfo()
	if err != nil || effect != 1 {
		return nil, err
	}
	// 注册后登陆
	token, err := login(in)
	if err != nil {
		return nil, err
	}

	return &userlogin.TokenReply{Token: token}, nil
}

// 用户登陆
func (s *server) UserLogin(ctx context.Context, in *userlogin.LoginRequest) (*userlogin.TokenReply, error) {
	seelog.Infof("Received: %v", in)
	// 检查用户是否注册
	userInfo, err := db.GetUserInfoByUserId(in.UserId)
	if err != nil || userInfo == nil {
		return nil, errors.New("login failed")
	}

	// 校验密码
	if b, err := utils.CheckDjangoPasswrod(config.AppConfig.DjangoAlgorithm, in.Password, userInfo.PasswordChar); !b || err != nil {
		return nil, errors.New("password is invalid")
	}

	// 生成token
	token, err := login(in)
	if err != nil {
		return nil, errors.New("login failed")
	}
	return &userlogin.TokenReply{Token: token}, nil
}

// token检查
func (s *server) TokenCheck(ctx context.Context, in *userlogin.TokenCheckRequest) (*userlogin.TokenCheckReply, error) {
	var flag int32 = LoginFailed
	// 解析传入的token
	userId, err := parseToken(in)
	if err != nil {
		return nil, err
	}

	// 根据用户获取redis存储的token
	tokenTmp, err := cache.GetToken(userId)
	if err != nil {
		return nil, err
	}
	// 判断传入的token是否与缓存一致，变检查token是否超时
	if tokenTmp.Token == in.Token && tokenTmp.ExpireTime > time.Now().Unix() {
		flag = LoginSuccess
	}

	// 检查通过相应的延长token过期时间（该功能满足用户长期登陆）
	err = cache.UpdateToken(tokenTmp)
	if err != nil {
		seelog.Errorf("updage failed, err:%v", err)
		return nil, err
	}
	return &userlogin.TokenCheckReply{Flag: flag}, nil
}

// stream双向流
type streamService struct {
	userlogin.UnimplementedStreamGreeterServer
}

func (s *streamService) StreamUserLogin(in userlogin.StreamGreeter_StreamUserLoginServer) error {
	var onece string
	tokenChan := make(chan string)
	oneceChan := make(chan string)
	go func() {
		i := 0
		for {
			data, err := in.Recv()
			if err != nil {
				return
			}
			seelog.Info(i, data)
			if data.Type == "onece" {
				onece = utils.GetRandomString(18)
				seelog.Info("set oneceChan")
				oneceChan <- onece
			} else {
				seelog.Info("set tokenchan two")
				loginRegister := userlogin.LoginRequest{
					UserId:   data.Param.UserId,
					DeviceId: data.Param.DeviceId,
					Onece:    data.Param.Onece,
					Password: data.Param.Password,
				}
				token, err := login(&loginRegister)
				if err != nil {
					seelog.Errorf("login failed")
				}
				tokenChan <- token
				break
			}
			i++
		}
	}()

	select {
	case onece := <-oneceChan:
		seelog.Info("tokenReply: onece", onece)
		reply := userlogin.TokenReply{Token: onece}
		in.Send(&reply)
	case <-time.After(1 * time.Second):
		fmt.Println("login onece time out")
		break
	}

	seelog.Info("tokenReply: token", in)
	select {
	case token := <-tokenChan:
		reply := userlogin.TokenReply{Token: token}
		in.Send(&reply)
		// case <-time.After(2 * time.Second):
		// 	fmt.Println("login token time out")
		// 	break
	}
	return nil
}

// 登陆
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

// 解析token
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

	return userId, nil
}

// 启动服务
func Start() {
	go func() {
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
		seelog.Infof("login_service end")
	}()
	go func() {
		seelog.Infof("login_service stream start")
		lis, err := net.Listen("tcp", config.AppConfig.StreamAddr)
		if err != nil {
			seelog.Errorf("failed to listen: %v", err)
		}
		s := grpc.NewServer()
		userlogin.RegisterStreamGreeterServer(s, &streamService{})
		if err := s.Serve(lis); err != nil {
			seelog.Errorf("failed to serve: %v", err)
		}
		seelog.Infof("login_service stream end")
	}()
}
