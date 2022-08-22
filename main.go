package main

import (
	"fmt"
	"iam-performance-test/db"
	"iam-performance-test/service/action"
	"iam-performance-test/service/krn"
)

type IAM struct {
	databaseClient *db.Client
}

func main() {

	//s := &IAM{}
	//
	//var err error
	//s.databaseClient, err = db.NewClient()
	//
	//if err != nil {
	//	fmt.Printf("Error occurred during connecting to PostgresSQL: %v", err)
	//}
	//
	//if err = s.databaseClient.Migrate(); err != nil {
	//	fmt.Errorf("Error on migrating tables: %v", err)
	//}

	//db.FillStatement()

	fmt.Println("CASE-1: search statement ids")
	actions := action.Action("iam:endpoint:read")
	principalKRN, _ := krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::user/743112f2-784c-4d66-8723-8f146ffc8191")
	resourceKRN, _ := krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::endpoint/a6036c75-6f9f-44a8-8ed7-2bda207abcb2")

	var statementIds []uint64
	db.SearchStatementIdsByParams(&statementIds, &db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
		Type:       "Allow",
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-2: exists")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::user/743112f2-784c-4d66-8723-8f146ffc8191")
	resourceKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::endpoint/*")

	db.ExistSearchStatementByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
		Type:       "Allow",
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-3: search resources")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::user/743112f2-784c-4d66-8723-8f146ffc8191")
	resourceKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::endpoint/*")

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
		Type:       "Allow",
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-4: search principals")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::user/743112f2-784c-4d66-8723-8f146ffc8191")
	resourceKRN, _ = krn.NewKRNFromString("krn:lfhrcadgzk:nuknowezyn::endpoint/*")

	db.SearchPrincipalsByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
		Type:       "Allow",
	})
}
