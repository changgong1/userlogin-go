package db

import (
	"database/sql"
	"errors"

	"github.com/cihub/seelog"
)

type UserInfo struct {
	Id             int64  `json:"id"`
	UserId         string `json:"user_id"`
	PasswordFactor string `json:"password_factor"`
	PasswordChar   string `json:"password_char"`
}

func (u *UserInfo) CheckField() error {
	if u.UserId == "" || u.PasswordFactor == "" || u.PasswordFactor == "" {
		seelog.Errorf("user info aren't enough")
		return errors.New("user info aren't enough")
	}
	return nil
}

func (u *UserInfo) AddUserInfo() (int64, error) {
	if err := u.CheckField(); err != nil {
		return 0, err
	}
	intSQL := "INSERT INTO user_info(user_id, password_factor, password_char) VALUES(?, ?, ?)"
	stmt, err := DbClient.GetDbMaster().Prepare(intSQL)
	if err != nil {
		seelog.Errorf("add user info failed. err:%v", err)
		return 0, err
	}
	res, err := stmt.Exec(u.UserId, u.PasswordFactor, u.PasswordChar)
	if err != nil {
		seelog.Errorf("add user info failed. err:%v", err)
		return 0, err
	}
	return res.RowsAffected()
}

func GetUserInfoByUserId(userId string) (*UserInfo, error) {
	u := UserInfo{}
	selSQL := `
	SELECT
		id, user_id, password_factor, password_char
	FROM
		user_info
	WHERE
		user_id = ? `

	err := DbClient.GetDbMaster().QueryRow(selSQL, userId).Scan(&u.Id, &u.UserId, &u.PasswordFactor, &u.PasswordChar)
	if err != nil {
		seelog.Errorf("add user info failed. err:%v", err)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}
