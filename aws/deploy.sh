#!/bin/sh -e

echo 'Building template...'

sam build

echo ''

sam deploy --guided
