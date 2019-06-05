package monitor

import (
	"sync"
	"testing"
	"time"
)

var elasticMutex = &sync.Mutex{}

func TestElasticReporter(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	id := startContainer(t, elasticMutex,"elasticsearch_metrics","elasticsearch_metrics",[]int{9200,9300},"http://127.0.0.1:9200")
	if id == "" {
		t.Logf("container could not be started, skipping test %s",t.Name())
		t.SkipNow()

		return
	}

	defer stopContainer(t,id)

	conf := Configuration{
		VDCName:"test-vdc",
		ElasticSearchURL:"http://127.0.0.1:9200",
		ElasticBasicAuth:true,
		ElasticUser:"admin",
		ElasticPassword:"ditasmetrics",
		IgnoreElastic:false,
	}
	messages := make(chan MeterMessage)

	reporter, err := NewElasticReporter(conf,messages)
	if err != nil {
		t.Fail()
		return
	}

	err = reporter.sendMeterMessage(
		MeterMessage{
			RequestID: "234567",
			OperationID:"someOp",
			Timestamp:time.Now(),
			RequestLenght:0,
			Kind:"asdfg",
			Method:"HEAD",
			RequestTime:1000,
			ResponseCode:400,
			ResponseLength:0,
		})

	if err != nil{
		t.Fatalf("failed to submit message to elastic %v",err)
	}
}
