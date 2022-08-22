package db

import (
	"database/sql"
	"fmt"
	"iam-performance-test/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Client struct {
	Client *gorm.DB
}

func NewClient() (*Client, error) {
	dsn := "host=localhost user=iam-perf password=root dbname=iam-perf port=5432 sslmode=disable TimeZone=Europe/Kiev"

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info)})

	if err != nil {
		return nil, err
	}

	return &Client{
		Client: db,
	}, nil
}

// CloseDB  DB connection.
func (c *Client) CloseDB() {
	var (
		db  *sql.DB
		err error
	)

	if db, err = c.Client.DB(); err != nil {
		fmt.Errorf("Error getting DB instance")
	}

	if err = db.Close(); err != nil {
		fmt.Errorf("Error disconnecting PostgreSQL")
	}

	fmt.Errorf("db instance successfully closed")
}

func (c *Client) Migrate() (err error) {
	defer c.CloseDB()

	if err = c.Client.AutoMigrate(&model.Statement{}); err != nil {
		return err
	}

	if err = c.CreateStatementGinIndexes(); err != nil {
		fmt.Errorf("Error creating a PostgreSQL statement gin indexes: %v", err)
	}

	return nil
}

func (c *Client) CreateStatementGinIndexes() error {
	if err := c.Client.Exec("CREATE INDEX IF NOT EXISTS idx_gin_statement_actions ON statements USING GIN (actions);").Error; err != nil {
		return err
	}

	if err := c.Client.Exec("CREATE INDEX IF NOT EXISTS idx_gin_statement_resources ON statements USING GIN (resources);").Error; err != nil {
		return err
	}

	if err := c.Client.Exec("CREATE INDEX IF NOT EXISTS idx_gin_statement_principals ON statements USING GIN (principals);").Error; err != nil {
		return err
	}

	return nil
}
