#!/bin/bash

# Run Celery worker on a cluster of nodes

celery -A worker \
worker \
--loglevel=debug \
--pidfile=/tmp/celery_iotfuzzer.pid \
-Q DiAnE \
--autoscale=72,1 \
-n worker@%h
