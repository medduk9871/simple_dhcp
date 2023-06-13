docker stop dhcp
docker rm dhcp
docker build -t pyhello:v1  .
docker run --name dhcp -it pyhello:v1
