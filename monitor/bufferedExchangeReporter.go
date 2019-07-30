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
	"encoding/json"
)

const BufferSize = 100

type MessageBuffer struct {
	data [BufferSize]*ExchangeMessage
	pos  int
}

func NewMessageBuffer() *MessageBuffer {
	buffer := &MessageBuffer{}
	buffer.Clear()
	return buffer
}

func (buffer *MessageBuffer) Add(message ExchangeMessage) {
	buffer.data[buffer.pos] = &message
	buffer.pos = (buffer.pos + 1) % BufferSize
}

func (buffer *MessageBuffer) AsSlice() []ExchangeMessage {
	data := make([]ExchangeMessage, 0)
	for _, v := range buffer.data {
		if v != nil {
			data = append(data, *v)
		}
	}
	return data
}

func (buffer *MessageBuffer) Clear() {
	buffer.pos = 0
	for i := range buffer.data {
		buffer.data[i] = nil
	}
}

type BufferedExchangeReporter struct {
	Buffer           *MessageBuffer
	ExchangeEndpoint string
}

//NewExchangeReporter creates a new exchange worker
func NewBufferedExchangeReporter(ExchangeEndpoint string) (*BufferedExchangeReporter, error) {
	//Wait for endpoint to become availible or timeout with error
	return &BufferedExchangeReporter{
		ExchangeEndpoint: ExchangeEndpoint,
		Buffer:           NewMessageBuffer(),
	}, nil
}

//Start will create a new worker process, for processing exchange Messages
func (er *BufferedExchangeReporter) Start() {

}

func (er *BufferedExchangeReporter) Dump() []byte {
	data := er.Buffer.AsSlice()
	er.Buffer.Clear()

	bytes, err := json.Marshal(data)
	if err != nil {
		return nil
	} else {
		return bytes
	}
}

func (er *BufferedExchangeReporter) Add(message ExchangeMessage) {
	er.Buffer.Add(message)
}

//Stop will terminate any running worker process
func (er *BufferedExchangeReporter) Stop() {

}
