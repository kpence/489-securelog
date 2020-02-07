#!/bin/bash

echo "testing"
echo "creating tables"
for i in {2..128}
do
  msg=$(seq -s= $i|tr -d '[:digit:]')
  ./test -w $msg
done
