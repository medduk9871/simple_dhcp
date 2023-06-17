docker stop dhcp
docker rm dhcp
docker build -t pyhello:v1 -f "./Dockerfile_rogue" .
docker run --name dhcp -it pyhello:v1
