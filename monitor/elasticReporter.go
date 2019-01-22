/*
 * Copyright 2018 Information Systems Engineering, TU Berlin, Germany
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is being developed for the DITAS Project: https://www.ditas-project.eu/
 */

package monitor

import (
	"context"
	"time"

	"github.com/DITAS-Project/TUBUtil/util"
	"github.com/olivere/elastic"
)

type elasticReporter struct {
	Queue    chan MeterMessage
	Client   *elastic.Client
	VDCName  string
	QuitChan chan bool
	ctx      context.Context
}

//NewElasticReporter creates a new reporter worker,
//will fail if no elastic client can be built
//otherwise retunrs a worker handler
func NewElasticReporter(config Configuration, queue chan MeterMessage) (elasticReporter, error) {

	util.SetLogger(logger)
	util.SetLog(log)

	util.WaitForAvailible(config.ElasticSearchURL, nil)

	client, err := elastic.NewClient(
		elastic.SetURL(config.ElasticSearchURL),
		elastic.SetSniff(false),
	)

	log.Debugf("using %s as ES endpoint", config.ElasticSearchURL)

	if err != nil {
		log.Error("failed to connect to elastic serach", err)
		return elasticReporter{}, err
	}

	reporter := elasticReporter{
		Queue:    queue,
		Client:   client,
		VDCName:  config.VDCName,
		QuitChan: make(chan bool),
		ctx:      context.Background(),
	}

	return reporter, nil
}

//Start creates a new worker process and waits for meterMessages
//can only be terminated by calling Stop()
func (er *elasticReporter) Start() {
	go func() {
		for {

			select {
			case work := <-er.Queue:
				//TODO
				log.Infof("reporting %s - %s", work.Client, work.Method)

				work.Timestamp = time.Now()

				_, err := er.Client.Index().Index(er.getElasticIndex()).Type("data").BodyJson(work).Do(er.ctx)

				if err != nil {
					log.Debug("failed to report mesurement to", err)
				} else {
					log.Debug("reported data to elastic!")
				}

			case <-er.QuitChan:
				// We have been asked to stop.
				log.Info("worker stopping")
				return
			}
		}
	}()
}

//Stop termintates this Worker
func (er *elasticReporter) Stop() {
	go func() {
		er.QuitChan <- true
	}()
}

func (er *elasticReporter) getElasticIndex() string {
	return util.GetElasticIndex(er.VDCName)
}
