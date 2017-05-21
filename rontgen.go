/*
   Copyright 2017 Florin Patan

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/xray"
)

type (
	Request struct {
		URL       string `json:"url"`
		Method    string `json:"method"`
		UserAgent string `json:"user_agent"`
		ClientIP  string `json:"client_ip"`
	}

	Response struct {
		Status        int `json:"status"`
		ContentLength int `json:"content_length"`
	}

	HTTP struct {
		Request  Request  `json:"request"`
		Response Response `json:"response"`
	}

	ECS struct {
		Container string `json:"container"`
	}

	EC2 struct {
		InstanceID string `json:"instance_id"`
		AZ         string `json:"availability_zone"`
	}

	XRay struct {
		Sdk        string `json:"sdk"`
		SdkVersion string `json:"sdk_version"`
		Package    string `json:"package"`
	}

	AWS struct {
		ECS  *ECS `json:"ecs"`
		EC2  *EC2 `json:"ec2"`
		XRay XRay `json:"xray"`
	}

	Service struct {
		Version string `json:"version"`
	}

	SubsegmentHTTP struct {
		Response Response `json:"response"`
	}

	SubsegmentAWS struct {
		Operation            string   `json:"operation"`
		Region               string   `json:"region"`
		RequestID            string   `json:"request_id"`
		Retries              int      `json:"retries"`
		IndexName            string   `json:"index_name"`
		ProjectionExpression string   `json:"projection_expression"`
		TableName            string   `json:"table_name"`
		ResourceNames        []string `json:"resource_names"`
	}

	Subsegment struct {
		ID            string         `json:"id"`
		Name          string         `json:"name"`
		StartTime     float64        `json:"start_time"`
		EndTime       float64        `json:"end_time"`
		Error         bool           `json:"error"`
		Throttle      bool           `json:"throttle"`
		Fault         bool           `json:"fault"`
		HTTP          SubsegmentHTTP `json:"http"`
		Aws           SubsegmentAWS  `json:"aws"`
		Namespace     string         `json:"namespace"`
		XForwardedFor bool           `json:"x_forwarded_for"`
	}

	Trace struct {
		Name        string                 `json:"name"`
		TraceID     string                 `json:"trace_id"`
		ID          string                 `json:"id"`
		StartTime   float64                `json:"start_time"`
		EndTime     float64                `json:"end_time"`
		Error       bool                   `json:"error"`
		Throttle    bool                   `json:"throttle"`
		Fault       bool                   `json:"fault"`
		Metadata    interface{}            `json:"metadata"`
		HTTP        *HTTP                  `json:"http"`
		Aws         *AWS                   `json:"aws"`
		Annotations map[string]interface{} `json:"annotations"`
		Service     *Service               `json:"service"`
		Origin      string                 `json:"origin"`
		Subsegments []Subsegment           `json:"subsegments"`
	}
)

func randStatusCode() int {
	codes := [...]int{200, 201, 202, 204, 301, 400, 401, 403, 405, 408, 419, 500, 501, 502, 503, 504}
	pos := mrand.Intn(len(codes))
	return codes[pos]
}

func randContentLength() int {
	return mrand.Intn(1024 * 1024)
}

func randString(len int) (string, error) {
	b := make([]byte, int(math.Ceil(float64(len)/2)))
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}

func genTraceID() *string {
	rs, err := randString(24)
	if err != nil {
		return nil
	}

	timeNow := time.Now()
	traceID := fmt.Sprintf("%d-%x-%s", 1, timeNow.Unix(), rs)

	return aws.String(traceID)
}

func genTrace() []byte {
	tid := genTraceID()
	if tid == nil {
		panic("tid nil")
	}
	traceID := *tid

	trID, err := randString(16)
	if err != nil {
		panic(err)
	}

	timeNow := float64(time.Now().UnixNano()) / float64(time.Second)
	segStart := timeNow
	segStop := segStart + 0.2

	subSegID, err := randString(16)
	if err != nil {
		panic(err)
	}
	subSegStart := segStart + 0.04
	subSegStop := subSegStart + 0.05

	metadata := struct {
		Default struct {
			OriginalURL string `json:"originalURL"`
		} `json:"default"`
	}{
		Default: struct {
			OriginalURL string `json:"originalURL"`
		}{
			OriginalURL: "someURL",
		},
	}

	annotations := map[string]interface{}{
		"anAnnotation": "annotation value",
	}

	mainStatus := randStatusCode()
	segStatus := randStatusCode()

	tRace := Trace{
		Name:      "someName",
		TraceID:   traceID,
		ID:        trID,
		StartTime: segStart,
		EndTime:   segStop,
		Error:     mainStatus > 399 && mainStatus < 500,
		Throttle:  mainStatus == 429,
		Fault:     mainStatus > 499,
		Metadata:  metadata,
		HTTP: &HTTP{
			Request: Request{
				URL:       "someURL",
				Method:    "GET",
				UserAgent: "some user-agent",
				ClientIP:  "127.0.0.1",
			},
			Response: Response{
				Status:        mainStatus,
				ContentLength: randContentLength(),
			},
		},
		Aws: &AWS{
			ECS: &ECS{
				Container: "1234567890ab",
			},
			EC2: &EC2{
				InstanceID: "i-1234567890abcdef1",
				AZ:         "eu-west-1a",
			},
			XRay: XRay{
				Sdk:        "X-Ray for Go",
				SdkVersion: "1.8.26",
				Package:    "aws-xray-sdk",
			},
		},
		Annotations: annotations,
		Service: &Service{
			Version: "v1.0.1",
		},
		Origin: "AWS::ECS::Container",
		Subsegments: []Subsegment{
			{
				ID:        subSegID,
				Name:      "DynamoDB",
				StartTime: subSegStart,
				EndTime:   subSegStop,
				Error:     segStatus > 399 && segStatus < 500,
				Throttle:  segStatus == 429,
				Fault:     segStatus > 499,
				HTTP: SubsegmentHTTP{
					Response: Response{
						Status:        segStatus,
						ContentLength: randContentLength(),
					},
				},
				Aws: SubsegmentAWS{
					Operation:            "Query",
					Region:               "eu-west-1",
					RequestID:            "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234",
					Retries:              0,
					IndexName:            "someIndexName",
					ProjectionExpression: "some, field, names",
					TableName:            "a-dynamo-table",
					ResourceNames: []string{
						"a-dynamo-table",
					},
				},
				Namespace: "aws",
			},
		},
	}

	trace, _ := json.Marshal(tRace)
	return trace
}

func main() {
	c, err := net.Dial("udp", "127.0.0.1:2000")
	if err != nil {
		panic(err)
	}

	header := append([]byte(`{"format": "json", "version": 1}`), byte('\n'))
	for range []int{1, 2, 3, 4, 5} {
		trace := genTrace()
		c.Write(append(header, trace...))
		time.Sleep(time.Duration(mrand.Intn(5)) * time.Second)
	}
}

func awsTrace() {

	tid := genTraceID()
	if tid == nil {
		panic("nil tid")
	}

	// ???
	tSg := &xray.TraceSummary{}

	tSeg, _ := json.Marshal(tSg)

	trSeg := &xray.Segment{
		Id:       tid,
		Document: aws.String(string(tSeg)),
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String("eu-west-1"),
		},
		Profile: "dlsniper",
	}))

	svc := xray.New(sess)

	trace := &xray.Trace{
		Duration: aws.Float64(0.006000041961669922),
		Id:       genTraceID(),
		Segments: []*xray.Segment{
			trSeg,
		},
	}
	traceStr, _ := json.Marshal(trace)

	params := &xray.PutTraceSegmentsInput{
		TraceSegmentDocuments: []*string{
			aws.String("TraceSegmentDocument"),
			aws.String(string(traceStr)),
		},
	}
	resp, err := svc.PutTraceSegments(params)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(resp)
}
