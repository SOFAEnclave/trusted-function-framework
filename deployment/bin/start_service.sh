#!/usr/bin/env bash

# To make sure aesmd service is started
/usr/bin/start_aesm.sh

# To start the service
./enclave_service_server
