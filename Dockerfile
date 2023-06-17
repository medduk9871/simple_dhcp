FROM python:3.9
WORKDIR /root
COPY . .

EXPOSE 67/udp
EXPOSE 68/udp

RUN pip install -r requirements.txt

CMD python dhcp_server.py domain
