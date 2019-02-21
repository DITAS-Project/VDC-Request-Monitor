#!/usr/bin/env bash
# Staging environment: 31.171.247.162
# Private key for ssh: /opt/keypairs/ditas-testbed-keypair.pem

# TODO state management? We are killing without careing about any operation the conainer could be doing.
ssh -i /opt/keypairs/ditas-testbed-keypair.pem cloudsigma@31.171.247.162 << 'ENDSSH'
sudo docker stop --time 20 vdc-request-monitor || true
sudo docker rm --force vdc-request-monitor || true
sudo docker rmi  ditas/vdc-request-monitor:v02
sudo docker pull ditas/vdc-request-monitor:v02

# Get the host IP
HOST_IP="$(ip route get 8.8.8.8 | awk '{print $NF; exit}')"

echo "{
    \"Endpoint\":\"http://${HOST_IP}:55581\",
    \"ElasticSearchURL\":\"http://127.0.0.1:9200\",
    \"VDCName\":\"testing\",
    \"Opentracing\":false,
    \"UseSelfSigned\":true,
    \"ForwardTraffic\":true,
    \"verbose\":true
}" > /tmp/rm.json


sudo docker stop --time 20  echo-server || true
sudo docker rm --force  echo-server || true
sudo docker run -p 55581:8080 -e DOCKER_HOST_IP=$HOST_IP --restart unless-stopped -d --name echo-server hashicorp/http-echo -listen=:8080 -text="hello world"

# Run the docker mapping the ports and passing the host IP via the environmental variable "DOCKER_HOST_IP"
sudo docker run -v /tmp/rm.json:/.config/monitor.json -p 55580:80 -e DOCKER_HOST_IP=$HOST_IP --restart unless-stopped -d --name vdc-request-monitor ditas/vdc-request-monitor:v02 /request-monitor --testing
ENDSSH
