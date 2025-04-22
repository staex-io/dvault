build:
	docker build -f Dockerfile -t dvaultd .

start:
	docker run --rm -it -p 2222:22 dvaultd

run_ipfs:
	docker run --rm --name ipfs_host \
		-p 4001:4001 -p 4001:4001/udp -p 8080:8080 -p 5001:5001 \
		ipfs/kubo:v0.33.2

connect:
	ssh-keygen -R '[127.0.0.1]:2222'
	ssh root@127.0.0.1 -p 2222
