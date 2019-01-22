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
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"testing"

	spec "github.com/DITAS-Project/blueprint-go"
)

func TestRequestMonitor_extractOperationId(t *testing.T) {

	blueprint, err := spec.ReadBlueprint(filepath.Join("..", "resources", "blueprint.json"))

	if err != nil {
		t.Fatalf("could not prepare test %+v", err)
	}

	opsMap := spec.AssembleOperationsMap(*blueprint)

	testData := buildTestData(opsMap)

	test(t, blueprint, testData)

}

func BenchmarkRequestMonitor_extractOperationId(b *testing.B) {
	blueprint, err := spec.ReadBlueprint(filepath.Join("..", "resources", "blueprint.json"))

	if err != nil {
		b.Fatalf("could not prepare test %+v", err)
	}

	opsMap := spec.AssembleOperationsMap(*blueprint)

	for i := 0; i < b.N*2; i++ {
		b.StopTimer()
		testData := buildTestData(opsMap)
		b.StartTimer()
		//once cold
		bench(b, blueprint, testData)
	}

}

func BenchmarkRequestMonitor_extractOperationIdCacheUse(b *testing.B) {
	blueprint, err := spec.ReadBlueprint(filepath.Join("..", "resources", "blueprint.json"))

	if err != nil {
		b.Fatalf("could not prepare test %+v", err)
	}

	opsMap := spec.AssembleOperationsMap(*blueprint)

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		testData := buildTestData(opsMap)
		b.StartTimer()
		//once cold
		bench(b, blueprint, testData)
		//once warm
		bench(b, blueprint, testData)
	}

}

func create(blueprint *spec.BlueprintType) RequestMonitor {
	return RequestMonitor{
		conf:      Configuration{},
		blueprint: blueprint,
		cache:     NewResoruceCache(blueprint),
	}
}

func test(b *testing.T, blueprint *spec.BlueprintType, testData map[string][]testURI) {

	//create monitor object
	mon := create(blueprint)

	for optID, tests := range testData {
		for _, test := range tests {
			id := mon.extractOperationId(test.Path, test.Method)
			if id != optID {
				b.Fatalf("failed to extract optID for: %s %s, expected:%s got:%s",
					test.Method, test.Path, optID, id)
			}
		}
	}

}

func bench(t *testing.B, blueprint *spec.BlueprintType, testData map[string][]testURI) {

	//create monitor object
	mon := create(blueprint)

	for optID, tests := range testData {
		for _, test := range tests {
			id := mon.extractOperationId(test.Path, test.Method)
			if id != optID {
				t.Logf("failed to extract optID for: %s %s, expected:%s got:%s",
					test.Method, test.Path, optID, id)
			}
		}
	}

}

type testURI struct {
	Path   string
	Method string
}

func buildTestData(opsMap map[string]spec.ExtendedOps) map[string][]testURI {
	testData := make(map[string][]testURI)
	for id, op := range opsMap {
		testData[id] = generateTestURIS(fmt.Sprintf("http://127.0.0.1:123123%s", op.Path), op.Method, 1000)
	}

	return testData
}

func generateTestURIS(path string, method string, num uint) []testURI {
	uris := make([]testURI, num)

	urlMatcher := regexp.MustCompile("{[a-zA-Z0-9\\-_]*}")

	for i := uint(0); i < num; i++ {
		uris[i] = testURI{
			Path: urlMatcher.ReplaceAllStringFunc(path, func(s string) string {
				//randomize ether text or numbers for each parameter
				if rand.Intn(10) > 5 {
					return RandStringRunes(5)
				}

				return fmt.Sprintf("%d", rand.Intn(5000))

			}),
			Method: method,
		}
	}

	return uris
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_%0123456789")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
