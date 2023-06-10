FROM python:3.9
WORKDIR /root
COPY . .

EXPOSE 67/udp
EXPOSE 68/udp

CMD ["python3", "dhcp_server.py"]
