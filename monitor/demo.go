package monitor

import (
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"strconv"
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
	router.HandleFunc("/slow", mon.slow).Methods("POST")
	router.HandleFunc("/reset", mon.reset).Methods("POST")
	router.HandleFunc("/failing", mon.fail).Methods("POST")
}

func (mon *RequestMonitor) slow(w http.ResponseWriter, req *http.Request) {
	if err := mon.Authenticate(req, mon.demoSecret); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		bytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Infof("could not apply slow mode due to parsing error %+v\n", err)
		}

		delay, err := strconv.Atoi(string(bytes))

		if err != nil {
			log.Infof("could not apply slow mode due to parsing error %+v\n", err)
		}
		mon.demoSlow = time.Duration(delay)
		log.Infof("entering slow mode with %d\n", mon.demoSlow)

		w.WriteHeader(200)
	}

}

func (mon *RequestMonitor) fail(w http.ResponseWriter, req *http.Request) {
	if err := mon.Authenticate(req, mon.demoSecret); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		mon.demoFail = true
		log.Info("entering fail mode with\n")

		w.WriteHeader(200)
	}
}

func (mon *RequestMonitor) kill(w http.ResponseWriter, req *http.Request) {
	if err := mon.Authenticate(req, mon.demoSecret); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		mon.death.Store(true)
		log.Info("entering kill mode \n")

		w.WriteHeader(200)
	}
}

func (mon *RequestMonitor) reset(w http.ResponseWriter, req *http.Request) {
	mon.death.Store(false)
	mon.demoSlow = 0
	mon.demoFail = false
	log.Info("reset all demo modes")

	w.WriteHeader(200)
}

func (mon *RequestMonitor) demo(w http.ResponseWriter, req *http.Request) bool {
	if mon.conf.DemoMode {
		if mon.death.Load() {
			return true
		}

		if mon.conf.SimulateInfrastructure {
			switch mon.infrastructureType {
			case "edge":
				time.Sleep(time.Millisecond * 2500)
				break
			case "fog":
				time.Sleep(time.Millisecond * 1000)
				break
			}
		}

		if mon.demoSlow >= 0 {
			time.Sleep(time.Millisecond * mon.demoSlow)
		}

		if mon.demoFail {
			http.Error(w, "demo says no", 500)
			return true
		}
	}

	//IMPORTANT: do not change unless you know what your are doing!
	return false
}
