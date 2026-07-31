#!/bin/bash

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout svr_key.pem -out svr_crt.pem -days 365 -nodes \
    -subj "/CN=localhost"

    