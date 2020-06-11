FROM ubuntu:18.04
#alpine:3.8
#ubuntu:latest
ENV LEVELDB_VER = 1.20
ENV LEVELDB_LINK = /usr/local/lib
ENV PYTHON_VER = 3.8

RUN apt-get update \
  && apt-get install -y python3-pip python3-dev libsnappy-dev -y libsodium-dev git wget curl \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip \
  && pip3 install msgpack  plyvel arrow zmq pyzmq Crypto PyNaCl \
  && wget https://github.com/google/leveldb/archive/v1.20.tar.gz \
  && tar xvf v1.20.tar.gz \
  && rm -f v1.20.tar.gz \
  && cd leveldb-1.20 \
  && make \
  && scp -r out-static/lib* out-shared/lib* '/usr/local/lib' \
  && cd include \
  && scp -r leveldb /usr/local/include \
  && ldconfig \
  && git clone https://github.com/promo888/test.git --branch x250 --single-branch \
  && cd test/venv \
  && export PYTHONPATH=$PYTHONPATH:`pwd`:/v \
  && ls \
  && cd v && ls && ls v1 \
  && python3 -V \
  && python3 v1.py


#EXPOSE 4444
#EXPOSE 5555
#EXPOSE 55555
#EXPOSE 6666
#EXPOSE 7777
#EXPOSE 8888
#EXPOSE 9999
#EXPOSE 80

#RUN["/bin/bash", "ls"]
#RUN mkdir -f test
#COPY /home/igor/PycharmProjects/test /test
#RUN cd test/venv/v && ls && python3 v1.py

ENTRYPOINT ["/bin/bash"]
#CMD /bin/bash
#"python3"
#docker build -t imagename:imagetag -f /tmp/mydockerfile context_dir
#sudo docker build -t fxcrypto:miner -f ./Dockerfile ./../node_data
#python missing: nacl sqlite3 asyncio aiohttp