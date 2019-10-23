package monitor

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

func (mon *RequestMonitor) setupDemo() error {
	if mon.conf.DemoMode {
		for k, m := range mon.blueprint.CookbookAppendix.Deployment.Infrastructures {
			if mon.conf.InfrastructureID == k {
				mon.infrastructureType = m.Type
			}
		}
	}
	return nil
}

func (mon *RequestMonitor) initDemoAPI(router *mux.Router) {
	router.HandleFunc("/kill", mon.kill).Methods("POST")
	router.HandleFunc("/relife", mon.relife).Methods("POST")
}

func (mon *RequestMonitor) kill(w http.ResponseWriter, req *http.Request) {
	mon.death.Store(true)
}

func (mon *RequestMonitor) relife(w http.ResponseWriter, req *http.Request) {
	mon.death.Store(false)
}

func (mon *RequestMonitor) demo(w http.ResponseWriter, req *http.Request) bool {
	if mon.death.Load() {
		return true
	}

	if mon.conf.DemoMode {
		switch mon.infrastructureType {
		case "edge":
			time.Sleep(time.Millisecond * 450)
			break
		case "fog":
			time.Sleep(time.Millisecond * 100)
			break
		}
	}

	//IMPORTANT: do not change unless you know what your are doing!
	return false
}
