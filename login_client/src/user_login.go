package src

import (
	"errors"
	"fmt"
	"time"

	lg "github.com/changgong1/userlogin-go/login_guide"
)

type UserLoginModel struct {
	Greeter string
	UserId  string
	Token   string
	Status  int
}

func (u *UserLoginModel) InitField() {
	u.Status = LoginStatusOut
}
func (u *UserLoginModel) CheckGreeter() (bool, error) {
	if u.Greeter == GreeterQuit {
		return true, nil
	}
	if u.Greeter == GreeterRegister || u.Greeter == GreeterStreamLogin || u.Greeter == GreeterLogin || u.Greeter == GetUserInfo {
		return false, nil
	}

	return false, errors.New("please enter register, login or quit")
}

func (u *UserLoginModel) ExecGreeter() error {
	if u.Greeter == GreeterRegister {
		in, err := u.loginOrRegisterParam()
		if err != nil {
			return nil
		}
		token, err := gLoginClient.Register(in)
		if err != nil {
			return err
		}
		u.Token = token
		u.Status = LoginStatusSuccess
	} else if u.Greeter == GreeterLogin {
		in, err := u.loginOrRegisterParam()
		if err != nil {
			return nil
		}

		token, err := gLoginClient.Login(in)
		if err != nil {
			return err
		}
		u.Token = token
		u.Status = LoginStatusSuccess
	} else if u.Greeter == GreeterStreamLogin {
		in, err := u.loginOrRegisterParam()
		if err != nil {
			return nil
		}
		inUser := &lg.LoginStreamRequest{
			Type:  u.Greeter,
			Param: in,
		}
		token, err := gLoginClient.StreamLogin(inUser)
		if err != nil {
			return err
		}
		u.Token = token
		u.Status = LoginStatusSuccess
	}
	go u.TokenCheck()
	return nil
}

func (u *UserLoginModel) loginOrRegisterParam() (*lg.LoginRequest, error) {
	in := &lg.LoginRequest{}
	userId, password, err := InputUserInfo()
	if err != nil {
		return nil, err
	}
	u.UserId = userId
	in.UserId = userId
	in.Password = password
	in.DeviceId = gLoginClient.DeviceId
	return in, nil
}
func (u *UserLoginModel) LoginOut() {
	u.Greeter = ""
	u.UserId = ""
	u.Token = ""
	u.Status = LoginStatusOut
	fmt.Println("login out success")
}

func InputUserInfo() (string, string, error) {
	fmt.Print("please enter user_id:")
	userId := ""
	fmt.Scanln(&userId)
	password := ""
	fmt.Print("please enter password:")
	fmt.Scanln(&password)
	return userId, password, nil
}
func (u *UserLoginModel) WaitOut() bool {
	out := ""
	fmt.Scanln(&out)
	if out == GetUserInfo {
		u.PrintUserInfo()
	}
	if out == GreeterOut {
		return true
	}
	return false
}

func (u *UserLoginModel) TokenCheck() {
	for {
		time.Sleep(3 * time.Second)
		in := &lg.TokenCheckRequest{Token: u.Token}
		b, err := gLoginClient.TokenCheck(in)
		if b == LoginStatusOut || err != nil {
			u.LoginOut()
			return
		}
	}
}

func (u *UserLoginModel) PrintUserInfo() {
	fmt.Println(u)
}

func (u *UserLoginModel) UserAction() {
	err := NewLoginClient()
	if err != nil {
		return
	}
	for {
		if u.Status == LoginStatusSuccess {
			fmt.Println("login success")
			if b := u.WaitOut(); b {
				u.LoginOut()
				continue
			} else {
				continue
			}
		} else {
			fmt.Print("please enter register, login or quit:")
			greeter := ""
			fmt.Scanln(&greeter)
			u.Greeter = greeter
			b, err := u.CheckGreeter()
			if b {
				break
			}
			if err != nil {
				continue
			}
			if u.Greeter == GetUserInfo {
				u.PrintUserInfo()
				continue
			}
		}
		err := u.ExecGreeter()
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
}
