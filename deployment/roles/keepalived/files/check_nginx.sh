#!/bin/bash

STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost)

if [ $STATUS_CODE -lt 200 ] || [ $STATUS_CODE -ge 400 ]; then
  exit 1
fi
