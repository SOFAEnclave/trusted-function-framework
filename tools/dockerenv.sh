#!/usr/bin/env bash

CURRDIR="$(pwd)"
REPONAME="$(basename $CURRDIR)"

IMAGE="antkubetee/kubetee-dev-ubuntu18.04-grpc-sgx-ssl:1.0"
CONTAINERNAME=${2:-"kubetee-dev-ubuntu1804-$REPONAME"}

show_help() {
    echo "Usage: $(basename $0) --init|--exec|--delete [container-name]"
}

docker_init() {
  sudo docker run  -itd \
      --name $CONTAINERNAME \
      --device=/dev/isgx \
      -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
      --net=host \
      -v $CURRDIR:/root/$REPONAME \
      -w /root/$REPONAME \
      --cap-add=SYS_PTRACE \
      --security-opt seccomp=unconfined \
      $IMAGE \
      bash
}

docker_exec() {
   sudo docker exec -it $CONTAINERNAME bash
}

docker_delete() {
   sudo docker rm -f $CONTAINERNAME
}

case "$1" in
    --init)     docker_init ;;
    --exec)     docker_exec ;;
    --delete)   docker_delete ;;
    -h|--help)  show_help ; exit 0 ;;
    *)          show_help ; exit 1 ;;
esac
