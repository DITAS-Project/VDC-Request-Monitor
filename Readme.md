# DITAS - VDC Request Monitor

The VDC Request Monitor is one of the monitoring sidecars used to observe the behavior of VDCs within the DITAS project. The agent acts and ingress controller to the VDC and observes any incoming and outgoing HTTP/HTTPS traffic.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

To install the go lang tools go to: [Go Getting Started](https://golang.org/doc/install)


To install dep, you can use this command or go to [Dep - Github](https://github.com/golang/dep):
```
curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
```



### Installing

For installation you have two options, building and running it on your local machine or using the docker approach.

For local testing and building for that you can follow the following steps:

install dependencies (only needs to be done once):

```
dep ensure
```

compile
```
CGO_ENABLED=0 GOOS=linux go build -a --installsuffix cgo --ldflags="-w -s -X main.Build=$(git rev-parse --short HEAD)" -o request-monitor
```

to run locally:
```
./request-monitor
```

For the docker approach, you can use the provided dockerfile to build a running artifact as a Docker container.

build the docker container:
```
docker build -t ditas/request-monitor -f Dockerfile.artifact . 
```

Attach the docker container to a VDC or other microservice like component:
```
docker run -v ./monitor.json:/opt/blueprint/monitor.json --pid=container:<APPID> -p <HTTP-port>:80 -p <HTTPS-port>:443 ditas/request-monitor
```
Here `<APPID>` must be the container ID of the application you want to observe. The `<HTTP-port>` and `<HTTPS-port>` can be set as desidered. Also, refer to the **Configuration** section for information about the `monitor.json`-config file.

## Running the tests

For testing you can use:
```
 go test ./...
```

For that make sure you have an elastic search running locally at the default port and some sort of local service that can process HTTP traffic, we recommend net-cat in listening mode `nc -l 8080`. 


## Configuration
To configure the agent, you can specify the following values in a JSON file:
 * ElasticSearchURL => The URL that all aggregated data is sent to
 * VDCName => the Name used to store the information under
 * Endpoint => the address of the service that traffic is forwarded to
 * Opentracing => indicates if an open tracing header should be set on every incoming request and if the frames should be sent to Zipkin
 * ZipkinEndpoint => the address of the Zipkin collector
 * UseACME => use lets encrypt to generate certificates for https
 * UseSelfSigned => let the agent generate self-signed certificates or use the ones provided in the config directory (same as the location of the config file). The files the agent is looking for are `cert.pem` and `key.pem`.
 * ForwardTraffic => allow the agent to forward all incoming and outgoing data to a secondary service for, e.g., auditing.
 * ExchangeReporterURL => if the *ForwardTraffic* is enabled, send the data to this location.
 * verbose => boolean to indicate if the agent should use verbose logging (recommended for debugging)

An example file could look like this:
```
{
    "Endpoint":"http://127.0.0.1:8080",
    "ElasticSearchURL":"http://127.0.0.1:9200",
    "VDCName":"tubvdc",
    "ZipkinEndpoint": http://localhost:9411,
    "Opentracing":false,
    "UseSelfSigned":true,
    "ForwardTraffic":false,
    "verbose":false
}
```

Alternatively, users can use flags with the same name to configure the agent.

## Built With

* [dep](https://github.com/golang/dep)
* [viper](https://github.com/spf13/viper)
* [oxy](https://github.com/vulcand/oxy)
* Zipkin
* OpenTracing
* [Let's Encrypt](golang.org/x/crypto/acme/autocert)
* [ElasticSearch](https://www.elastic.co/)

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## License

This project is licensed under the Apache 2.0 - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

This is being developed for the [DITAS Project](https://www.ditas-project.eu/)
