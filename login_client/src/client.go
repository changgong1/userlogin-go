package src

import (
	"context"
	"fmt"
	"time"

	"github.com/changgong1/userlogin-go/login_client/config"
	lg "github.com/changgong1/userlogin-go/login_guide"
	"google.golang.org/grpc"
)

const GreeterRegister = "register"
const GreeterLogin = "login"
const GreeterOut = "out"
const GreeterTokenCheck = "tokenCheck"
const GreeterQuit = "quit"
const GetUserInfo = "getu"
const LoginStatusOut = 1
const LoginStatusSuccess = 0

var gLoginClient *LoginClient

func NewLoginClient() error {
	c := LoginClient{}

	ctx1, cel := context.WithTimeout(context.Background(), time.Second*1)
	defer cel()
	conn, err := grpc.DialContext(ctx1, config.AppConfig.Addr, grpc.WithBlock(), grpc.WithInsecure())
	// seelog.Errorf("did not connect: %v", err)
	if err != nil {
		fmt.Println("did not connect: ", err)
		return err
	}
	c.conn = conn
	c.GreeterClient = lg.NewGreeterClient(conn)
	gLoginClient = &c
	return nil
}

type LoginClient struct {
	DeviceId      string
	conn          *grpc.ClientConn
	GreeterClient lg.GreeterClient
}

func (l *LoginClient) initLoginClient(conn *grpc.ClientConn) {
	l.conn = conn
}

func (l *LoginClient) Register(in *lg.LoginRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := l.GreeterClient.UserRegister(ctx, in)
	if err != nil {
		// seelog.Error("could not greet: %v", err)
		return "", err
	}
	return r.GetToken(), nil
}

func (l *LoginClient) Login(in *lg.LoginRequest) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := l.GreeterClient.UserLogin(ctx, in)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return r.GetToken(), nil
}

func (l *LoginClient) TokenCheck(in *lg.TokenCheckRequest) (int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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
}
