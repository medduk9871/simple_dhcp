docker stop dhcp
docker rm dhcp
docker build -t pyhello:v1 -f "./Dockerfile" .
docker run --name dhcp -it pyhello:v1
