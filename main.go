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
	//
	//db.FillStatement()

	fmt.Println("CASE-1: Evaluate if user has access to one resource")
	actions := action.Action("iam:endpoint:read")
	principalKRN, _ := krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::user/237d750b-a6b3-478c-b81c-aa87dba9fff9")
	resourceKRN, _ := krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::endpoint/7971a90a-6c70-4784-bc46-55b9b7591627")

	db.ExistSearchStatementByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-2.1 (wildcard krn): Evaluate if user has access to several resources")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::user/237d750b-a6b3-478c-b81c-aa87dba9fff9")
	resourceKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::endpoint/*")

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-2.2 (specific krns): Evaluate if user has access to several resources")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::user/237d750b-a6b3-478c-b81c-aa87dba9fff9")
	resourceKRNs := krn.NewKRNArrayFromStrings("krn:yfbyqflueh:cwwardhrry::endpoint/149629b6-3264-4f23-ae3c-dd569270459a", "krn:yfbyqflueh:cwwardhrry::endpoint/7971a90a-6c70-4784-bc46-55b9b7591627", "krn:yfbyqflueh:cwwardhrry::endpoint/b840aa19-f95b-4a2b-ae6e-99e18b75432b")

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRNs,
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-3: Retrieve one allowed resource.")
	actionParam := "iam:endpoint:read"
	resourceParam := "krn:iam:kaa::endpoint/0aeaa28f-9bf0-4504-8c53-fd105e57131a"
	principalParam := "krn:iam:kaa::user/829ede0e-c5ef-46f2-9f25-b54613cc9a17"
	//db.FillStatementOneAllowedResource(actionParam, resourceParam, principalParam)
	actions = action.Action(actionParam)
	principalKRN, _ = krn.NewKRNFromString(principalParam)
	resourceKRN, _ = krn.NewKRNFromString(resourceParam)

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-4: Retrieve all resources: all requested resources are allowed")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::*")
	resourceKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:*")

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-5: Retrieve all resources: all requested resources are allowed")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:*")
	resourceKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:cwwardhrry::endpoint/*")

	db.SearchResourcesByParams(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Println("-----------------------------------------------------------------------------------------------------")

	fmt.Println("CASE-6: Retrieve one grouped by type")
	actions = action.Action("iam:endpoint:read")
	principalKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:*")
	resourceKRN, _ = krn.NewKRNFromString("krn:yfbyqflueh:*")

	allowed, denied, _ := db.SearchResourcesByParamsGroupingByType(&db.EvaluatePermissionRequest{
		Actions:    actions.MatchingActionsString(),
		Resources:  resourceKRN.MatchingKRNs(),
		Principals: principalKRN.MatchingKRNs(),
	})

	fmt.Printf("Allowed: %v \n", allowed)
	fmt.Printf("Denied: %v \n", denied)
}
