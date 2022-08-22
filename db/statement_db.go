package db

import (
	"fmt"
	"iam-performance-test/model"
	"iam-performance-test/service/action"
	"iam-performance-test/service/krn"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ResourceCount  = 10
	PrincipalCount = 5
	ServiceCount   = 100
	StatementCount = 10_000
	BatchSize      = 500
	newline        = `
	`
)

type EvaluatePermissionRequest struct {
	Actions    []string
	Resources  []string
	Principals []string
	Type       string
}

func SearchStatementIdsByParams(statementIds *[]uint64, request *EvaluatePermissionRequest) {

	start := time.Now()
	query := "select s.id from statements s where 1 = 1 "

	if request.Type != "" {
		query += newline + "AND type = ?"
	}

	if len(request.Actions) != 0 {
		query += whereClause(request.Actions, "actions")
	}

	if len(request.Resources) != 0 {
		query += whereClause(request.Resources, "resources")
	}

	if len(request.Principals) != 0 {
		query += whereClause(request.Principals, "principals")
	}

	client, err := NewClient()

	if err != nil {
		fmt.Printf("Error occurred during connecting to PostgresSQL: %v", err)
	}

	client.Client.Raw(query, request.Type).Scan(statementIds)
	fmt.Printf("Search took: %s; Result length: %s\n", time.Since(start).String(), strconv.Itoa(len(*statementIds)))
}

func ExistSearchStatementByParams(request *EvaluatePermissionRequest) bool {
	var isExists bool

	start := time.Now()
	query := "select exists(select s.id from statements s where 1 = 1 "

	if len(request.Actions) != 0 {
		query += whereClause(request.Actions, "actions")
	}

	if len(request.Resources) != 0 {
		query += whereClause(request.Resources, "resources")
	}

	if len(request.Principals) != 0 {
		query += whereClause(request.Principals, "principals")
	}

	query += ")"

	client, err := NewClient()

	if err != nil {
		fmt.Printf("Error occurred during connecting to PostgresSQL: %v", err)
	}

	client.Client.Raw(query).Scan(&isExists)

	fmt.Printf("Search took: %s; Result:  %s\n", time.Since(start).String(), strconv.FormatBool(isExists))
	return isExists
}

func SearchResourcesByParams(request *EvaluatePermissionRequest) *[]string {
	var resources []string

	start := time.Now()
	query := "select distinct unnest(s.resources) from statements s where 1 = 1 "

	if len(request.Actions) != 0 {
		query += whereClause(request.Actions, "actions")
	}

	if len(request.Resources) != 0 {
		query += whereClause(request.Resources, "resources")
	}

	if len(request.Principals) != 0 {
		query += whereClause(request.Principals, "principals")
	}

	client, err := NewClient()

	if err != nil {
		fmt.Printf("Error occurred during connecting to PostgresSQL: %v", err)
	}

	client.Client.Raw(query).Scan(&resources)

	fmt.Printf("Search took: %s; Result length:  %s\n", time.Since(start).String(), strconv.Itoa(len(resources)))
	return &resources
}

func SearchPrincipalsByParams(request *EvaluatePermissionRequest) *[]string {
	var resources []string

	start := time.Now()
	query := "select distinct unnest(s.principals) from statements s where 1 = 1 "

	if len(request.Actions) != 0 {
		query += whereClause(request.Actions, "actions")
	}

	if len(request.Resources) != 0 {
		query += whereClause(request.Resources, "resources")
	}

	if len(request.Principals) != 0 {
		query += whereClause(request.Principals, "principals")
	}

	client, err := NewClient()

	if err != nil {
		fmt.Printf("Error occurred during connecting to PostgresSQL: %v", err)
	}

	client.Client.Raw(query).Scan(&resources)

	fmt.Printf("Search took: %s; Result length:  %s\n", time.Since(start).String(), strconv.Itoa(len(resources)))
	return &resources
}

func whereClause(values []string, column string) string {
	where := newline

	where += fmt.Sprintf(`AND "%s" && ARRAY[%v]`, column, prepareArray(values))

	return where
}

func prepareArray(values []string) string {
	for i, value := range values {
		values[i] = `'` + value + `'`
	}

	return strings.Join(values, ",")
}

func FillStatement() {
	client, _ := NewClient()

	for i := 0; i < ServiceCount; i++ {
		var statements []*model.Statement
		serviceName := generateRandomString()

		for j := 0; j < StatementCount; j++ {
			if j%10 == 0 {
				statements = append(statements, buildStatement(serviceName, generateRandomString(), true))
			} else {
				statements = append(statements, buildStatement(serviceName, generateRandomString(), false))
			}
		}

		client.Client.CreateInBatches(statements, BatchSize)
		fmt.Printf("%d of %d statements created\n", (i+1)*StatementCount, ServiceCount*StatementCount)
	}

	println("Statement filled")
}

func buildStatement(serviceName string, tenantName string, includeServiceWildcard bool) *model.Statement {
	var actions = []action.Action{"iam:endpoint:read", "iam:endpoint:write", "iam:endpoint:delete"}

	var resources []*krn.KRN
	for i := 0; i < ResourceCount; i++ {
		var resourceKrn *krn.KRN
		if i == 0 && includeServiceWildcard {
			resourceKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":*")
		} else if i == 1 {
			resourceKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":" + tenantName + "::*")
		} else {
			resourceKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":" + tenantName + "::endpoint/" + uuid.New().String())
		}
		resources = append(resources, resourceKrn)
	}

	var principals []*krn.KRN
	for i := 0; i < PrincipalCount; i++ {
		var principalKrn *krn.KRN
		if i == 0 && includeServiceWildcard {
			principalKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":*")
		} else if i == 1 {
			principalKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":" + tenantName + "::*")
		} else {
			principalKrn, _ = krn.NewKRNFromString("krn:" + serviceName + ":" + tenantName + "::user/" + uuid.New().String())
		}
		principals = append(principals, principalKrn)
	}

	types := []string{"Allow", "Deny"}
	randomIdx := rand.Intn(len(types))

	return &model.Statement{Type: types[randomIdx], Actions: actions, Resources: resources, Principals: principals}
}

func generateRandomString() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")

	s := make([]rune, 10)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}

	return string(s)
}
