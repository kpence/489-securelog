#!/bin/bash

echo "testing"
echo "creating tables"
#for i in {2..12}
#do
  #msg=$(seq -sa $i|tr -d '[:digit:]')
  #echo $i
#done

rm ./output.txt

echo "Write 1"
./test -w 1-ADSamuel-
echo "Read 1"
./test -r 999
echo "Write 2"
./test -w 2-ADCharles-
echo "Read 2"
./test -r 999
echo "Write 3"
./test -w 3-ADSamuel-R1-
echo "Read 3"
./test -r 999
#./test -w 4-ANKyle-
#./test -r 999
#./test -w 5-ANKyle-R1-
#./test -r 999
#./test -w 6-LDSamuel-R1-
#./test -r 999
#./test -w 7-LDSamuel-
#./test -r 999
#./test -w 9-LNKyle-R1-
#./test -r 999
#./test -w 10-LDCharles-
#./test -r 999
#./test -w 11-LNKyle-
#./test -r 999
