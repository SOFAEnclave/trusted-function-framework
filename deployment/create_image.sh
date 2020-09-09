#!/usr/bin/env bash

THISDIR="$(readlink -f $(dirname $0))"
DOCKERFILE="${1:-${THISDIR}/dockerfile/Dockerfile}"
IMAGENAME="${2:-kubetee-enclave-service:1.0}"
#IMAGETAG="$(date +%F-%H%M%S)"

if [ ! -f "$DOCKERFILE" ] ; then
    echo "Usage: $0 <path-to-dockerfile>"
    exit 1
fi

cd $THISDIR
BUILDOUTDIR="$THISDIR/buildout"
echo "Copy release files to $BUILDOUTDIR" && \
mkdir -p $BUILDOUTDIR && \
rm -rf $BUILDOUTDIR/* && \
cp -r ../build/out/* $BUILDOUTDIR && \
rm -rf $BUILDOUTDIR/libenclave_service.so
rm -rf $BUILDOUTDIR/identity.keypair*
rm -rf $BUILDOUTDIR/ias_report.response*
rm -rf $BUILDOUTDIR/*.a
ls $BUILDOUTDIR

if [ -e "$BUILDOUTDIR/enclave_service.signed.so" ] ; then
    echo "IMAGE: $IMAGENAME"
    sudo docker build -f ${DOCKERFILE} -t ${IMAGENAME} . && \
    sudo docker images | grep "${IMAGENAME%:*}"
else
  echo "There is no signed enclave named enclave_service.signed.so"
  echo "Please build the repository and sign the enclaves firstly!"
  exit 1
fi
