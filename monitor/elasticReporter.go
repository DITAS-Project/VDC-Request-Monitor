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
	"fmt"
	"time"

	util "github.com/DITAS-Project/TUBUtil"
	"github.com/olivere/elastic"
)

type ElasticReporter struct {
	Queue    chan MeterMessage
	Client   *elastic.Client
	VDCName  string
	QuitChan chan bool
	ctx      context.Context
}

//NewElasticReporter creates a new reporter worker,
//will fail if no elastic client can be built
//otherwise retunrs a worker handler
func NewElasticReporter(config Configuration, queue chan MeterMessage) (ElasticReporter, error) {

	util.SetLogger(logger)
	util.SetLog(log)

	if !config.IgnoreElastic {
		var client *elastic.Client
		var err error
		if config.ElasticBasicAuth {
			_ = util.WaitForAvailibleWithAuth(config.ElasticSearchURL, []string{config.ElasticUser, config.ElasticPassword}, nil)

			client, err = elastic.NewClient(
				elastic.SetURL(config.ElasticSearchURL),
				elastic.SetSniff(false),
				elastic.SetBasicAuth(config.ElasticUser, config.ElasticPassword),
			)
		} else {
			_ = util.WaitForAvailible(config.ElasticSearchURL, nil)
			client, err = elastic.NewClient(
				elastic.SetURL(config.ElasticSearchURL),
				elastic.SetSniff(false),
			)
		}

		if err != nil {
			log.Errorf("failed to connect to elastic serach %+v", err)
			return ElasticReporter{}, err
		}

		log.Debugf("using %s as ES endpoint", config.ElasticSearchURL)

		reporter := ElasticReporter{
			Queue:    queue,
			Client:   client,
			VDCName:  config.VDCName,
			QuitChan: make(chan bool),
			ctx:      context.Background(),
		}

		return reporter, nil
	}

	reporter := ElasticReporter{
		Queue:    queue,
		VDCName:  config.VDCName,
		QuitChan: make(chan bool),
		ctx:      context.Background(),
	}

	return reporter, nil

}

//TODO: XXX needs testing
//Start creates a new worker process and waits for meterMessages
//can only be terminated by calling Stop()
func (er *ElasticReporter) Start() {
	go func() {
		for {
			select {
			case work := <-er.Queue:
				_ = er.sendMeterMessage(work)
			case <-er.QuitChan:
				// We have been asked to stop.
				log.Info("worker stopping")
				return
			}
		}
	}()
}

func (er *ElasticReporter) sendMeterMessage(work MeterMessage) error {
	log.Infof("reporting %s - %s", work.Client, work.Method)
	work.Timestamp = time.Now()
	if er.Client != nil {
		_, err := er.Client.Index().Index(er.getElasticIndex()).Type("data").BodyJson(work).Do(er.ctx)
		if err != nil {
			log.Debug("failed to report measurement to", err)
			return err
		} else {
			log.Debug("reported data to elastic!")
			return nil
		}
	} else {
		return fmt.Errorf("no client avaliblibe")
	}
}

//Stop termintates this Worker
func (er *ElasticReporter) Stop() {
	er.QuitChan <- true
}

func (er *ElasticReporter) getElasticIndex() string {
	return util.GetElasticIndex(er.VDCName)
}
