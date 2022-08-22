package model

type Statement struct {
	ID         uint        `gorm:"primaryKey"`
	Actions    actionArray `gorm:"column:actions;type:text[];index:idx_gin_statement_actions"              json:"actions"        validate:"required,gt=0,dive,required,action"`
	Resources  krnArray    `gorm:"column:resources;type:text[]"            json:"resources"      validate:"required,gt=0,dive,required,krn"`
	Principals krnArray    `gorm:"column:principals;type:text[]"           json:"principals"     validate:"dive,required,krn"`
	Type       string      `gorm:"column:type;type:string;size:256"      json:"type"         validate:"required,oneof=allow deny"`
	Effect     string      `gorm:"column:type;type:string;size:256"      json:"type"         validate:"required,oneof=allow deny"`
}

type Statements []Statement
