build:
	docker build -f Dockerfile -t dvaultd .

start_server:
	docker run --rm -it -e TAG=server --name dvaultd_server dvaultd

start_client:
	docker run --rm -it -e TAG=client --name dvaultd_client dvaultd

run_ipfs:
	docker run --rm --name ipfs_host \
		-p 4001:4001 -p 4001:4001/udp -p 8080:8080 -p 5001:5001 \
		ipfs/kubo:v0.34.1

connect_server:
	docker exec -it dvaultd_server bash

connect_client:
	docker exec -it dvaultd_client bash

server_ip:
	docker network inspect bridge | jq -r '.[0].Containers[] | select(.Name=="dvaultd_server") | .IPv4Address'
