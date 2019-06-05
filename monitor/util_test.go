package monitor

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func startContainer(t *testing.T,mutex *sync.Mutex, containerName string, imageName string,ports []int, healthCheckUrl string) string {
	mutex.Lock()
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Error(err)
		t.SkipNow()
		return ""
	}

	t.Log("connected to docker")

	//remove old one if present
	args, err := filters.ParseFlag(fmt.Sprintf("name=%s",containerName), filters.NewArgs())
	if err != nil {
		t.Error(err)
		t.SkipNow()
		return ""
	}
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		Filters: args,
	})
	if err != nil {
		t.Error(err)
		t.SkipNow()
		return ""
	}

	for _, ct := range containers {
		_ = cli.ContainerStop(ctx, ct.ID, nil)
		_ = cli.ContainerRemove(ctx, ct.ID, types.ContainerRemoveOptions{
			Force: true,
		})
		t.Log("removed old container")
	}

	portMap :=  nat.PortSet{}
	bindingMap := nat.PortMap{}
	for _,portNumber := range ports {
		var port nat.Port
		port = nat.Port(fmt.Sprintf("%d/tcp", portNumber))
		portMap[port] = struct{}{}

		bindingMap[port] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: fmt.Sprintf("%d",portNumber),
			},
		}
	}

	//create new container
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: imageName,
		ExposedPorts: portMap,
	}, &container.HostConfig{
		AutoRemove: true,
		PortBindings: bindingMap,
	}, nil, containerName)
	if err != nil {
		t.Error(err)
		return ""
	}
	t.Logf("created %s",containerName)

	//start
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{

	}); err != nil {
		t.Error(err)
		return ""
	}
	t.Logf("started %s",containerName)
	printContainerLogs(t,resp.ID)
	//configure
	_ = waitForConnection(healthCheckUrl, nil)
	mutex.Unlock()
	return resp.ID
}

func stopContainer(t *testing.T, id string) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Error(err)
	}

	if err := cli.ContainerStop(ctx, id, nil); err != nil {
		t.Error(err)
	}
}

func printContainerLogs(t *testing.T,id string){
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Error(err)
	}

	out, err := cli.ContainerLogs(ctx, id, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return
	}

	_, _ = io.Copy(os.Stdout, out)
}

func waitForConnection(url string, timeout *time.Duration) error {

	signal := make(chan bool)

	go func() {
		backoff := 2 * time.Second
		for {
			resp, err := http.Head(url)
			if err != nil {
				fmt.Printf("tried to connect to %s %+v waiting %d seconds\n",url, err, backoff)

			} else {
				if resp.StatusCode <= 401 {
					fmt.Printf("got resp from %s %d\n",url,resp.StatusCode)
					signal <- true
				} else {
					fmt.Printf("tried to connect to  %s  %d waiting %d seconds\n",url, resp.StatusCode, backoff)
				}
			}
			time.Sleep(backoff)
			backoff = backoff * 2
		}
	}()

	if timeout != nil {
		select {
		case <-signal:
			return nil
		case <-time.After(*timeout):
			return fmt.Errorf("all timedout - %s could not be reached",url)
		}
	} else {
		<-signal
		return nil
	}

}
