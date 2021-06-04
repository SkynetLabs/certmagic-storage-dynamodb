FROM golang

RUN apt-get update -y

COPY . /certmagic-storage-skydb

WORKDIR /certmagic-storage-skydb

RUN go get ./...

CMD ["bash"]
