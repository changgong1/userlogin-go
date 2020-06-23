package db

import (
	"database/sql"
	"sync"

	"github.com/cihub/seelog"
	_ "github.com/go-sql-driver/mysql"
)

// sql连接配置
type DbInstConfig struct {
	Driver string
	Url    string
}

// sql组
type DBConfig struct {
	Instances map[string]DbInstConfig
}

// 一个数据库连接
type Database struct {
	Config  *DBConfig // 配置信息
	*sql.DB           // 数据库连接
}

// 创建一个连接
func NewDatabase(dbName string, config *DBConfig) (*Database, error) {
	instConfig := config.Instances[dbName]

	database, err := sql.Open(instConfig.Driver, instConfig.Url)
	if err != nil {
		seelog.Errorf("open database error %v", err)
		return nil, err
	}

	if err := database.Ping(); err != nil {
		seelog.Errorf("ping database error %v", err)
		return nil, err
	}
	return &Database{
		Config: config,
		DB:     database,
	}, nil
}

// 多个数据库连接
type Databases struct {
	config    *DBConfig
	instances map[string]*Database
	lock      sync.Mutex
}

// 初始化多个数据库连接
func GetDatabases(config *DBConfig) *Databases {
	return &Databases{config: config, instances: make(map[string]*Database), lock: sync.Mutex{}}
}

// 从多个连接中获取一个
func (ds *Databases) GetDatabase(dbName string) (*Database, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	if oldDb, ok := ds.instances[dbName]; !ok {
		database, err := NewDatabase(dbName, ds.config)
		if err != nil {
			seelog.Errorf("init database error %v", err)
			return nil, err
		}
		ds.instances[dbName] = database
		return database, nil
	} else {
		return oldDb, nil
	}
}

// 数据库连接类
type BaseDatabaseModel struct {
	DBs *Databases
}

func (d *BaseDatabaseModel) ConnDbTest() error {
	_, err := d.DBs.GetDatabase("master")
	return err
}

func (d *BaseDatabaseModel) GetDbMaster() *Database {
	dbs, _ := d.DBs.GetDatabase("master")
	return dbs
}

var DbClient *BaseDatabaseModel

func NewBaseDabase(config *DBConfig) error {
	dbs := GetDatabases(config)
	DbClient = &BaseDatabaseModel{
		DBs: dbs,
	}

	return DbClient.ConnDbTest()
}
