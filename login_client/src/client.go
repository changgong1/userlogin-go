package src

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/changgong1/userlogin-go/login_client/config"
	lg "github.com/changgong1/userlogin-go/login_guide"
	"github.com/changgong1/userlogin-go/login_service/utils"
	"google.golang.org/grpc"
)

const GreeterRegister = "register"
const GreeterLogin = "login"
const GreeterStreamLogin = "streamlogin"
const GreeterOut = "out"
const GreeterTokenCheck = "tokenCheck"
const GreeterQuit = "quit"
const GetUserInfo = "getu"
const LoginStatusOut = 1
const LoginStatusSuccess = 0

var gLoginClient *LoginClient

func NewLoginClient() error {
	c := LoginClient{}

	ctx1, cel := context.WithTimeout(context.Background(), config.AppConfig.ReqTimeOut*time.Second)
	defer cel()
	conn, err := grpc.DialContext(ctx1, config.AppConfig.Addr, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		fmt.Println("did not connect: ", config.AppConfig.Addr, err)
		return err
	}
	c.conn = conn
	c.GreeterClient = lg.NewGreeterClient(conn)
	// stream
	streamConn, err := grpc.DialContext(ctx1, config.AppConfig.StreamAddr, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		fmt.Println("did not connect: ", config.AppConfig.StreamAddr, err)
		return err
	}
	c.streamconn = streamConn
	c.StreamGreeterClient = lg.NewStreamGreeterClient(streamConn)
	gLoginClient = &c
	return nil
}

type LoginClient struct {
	DeviceId            string
	conn                *grpc.ClientConn
	GreeterClient       lg.GreeterClient
	streamconn          *grpc.ClientConn
	StreamGreeterClient lg.StreamGreeterClient
}

func (l *LoginClient) initLoginClient(conn *grpc.ClientConn) {
	l.conn = conn
}

func (l *LoginClient) Register(in *lg.LoginRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.AppConfig.ReqTimeOut*time.Second)
	defer cancel()
	r, err := l.GreeterClient.UserRegister(ctx, in)
	if err != nil {
		return "", err
	}
	return r.GetToken(), nil
}

func (l *LoginClient) Login(in *lg.LoginRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.AppConfig.ReqTimeOut*time.Second)
	defer cancel()
	r, err := l.GreeterClient.UserLogin(ctx, in)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return r.GetToken(), nil
}

func (l *LoginClient) StreamLogin(in *lg.LoginStreamRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.AppConfig.ReqTimeOut*time.Second)
	defer cancel()
	recv, err := l.StreamGreeterClient.StreamUserLogin(ctx)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	tokenChan := make(chan string)
	oneceChan := make(chan string)
	// 发送流
	go func() {
		for {
			in.Type = "onece"
			recv.Send(in)
			break
		}
	}()
	// 接受流
	go func() {
		i := 0
		for {
			reply, err := recv.Recv()
			if err != nil {
				fmt.Println(err)
				return
			}
			if i == 0 {
				oneceChan <- reply.Token
			} else {
				tokenChan <- reply.Token
				break
			}
			i++
		}
	}()

	// 发送第二次流
	select {
	case <-oneceChan:
		signStr, err := json.Marshal(in)
		if err != nil {
			fmt.Println(err)
		}
		in.Param.Signature = utils.Sha256(string(signStr))
		in.Type = ""
		fmt.Println("send in two:", in)
		recv.Send(in)
		break
	case <-time.After(config.AppConfig.ReqTimeOut * time.Second):
		fmt.Println("login time out")
		break
	}

	// 结束
	t := ""
	select {
	case t = <-tokenChan:
		fmt.Println(t)
	case <-time.After(config.AppConfig.ReqTimeOut * time.Second):
		return "", errors.New("login time out")
	}
	return t, nil
}

func (l *LoginClient) TokenCheck(in *lg.TokenCheckRequest) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.AppConfig.ReqTimeOut*time.Second)
	defer cancel()
	r, err := l.GreeterClient.TokenCheck(ctx, in)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	return r.GetFlag(), nil
}

func (l *LoginClient) Close() {
	l.conn.Close()
	l.streamconn.Close()
}
