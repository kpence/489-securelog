#!/bin/bash

echo "testing"
echo "creating tables"
#for i in {2..12}
#do
  #msg=$(seq -sa $i|tr -d '[:digit:]')
  #echo $i
#done

rm ./log1

./logappend -T 1 -K secret -A -D Alice -F log1
echo "test 2"
./logappend -T 2 -K secret -A -N Bob -F log1
echo "test 3"
./logappend -T 3 -K secret -A -D Alice -R 1 -F log1
./logappend -T 4 -K secret -A -N Bob -R 1 -F log1
./logappend -T 5 -K secret -L -D Alice -R 1 -F log1
./logappend -T 6 -K secret -A -D Alice -R 2 -F log1
./logappend -T 7 -K secret -L -D Alice -R 2 -F log1
./logappend -T 8 -K secret -A -D Alice -R 3 -F log1
./logappend -T 9 -K secret -L -D Alice -R 3 -F log1
./logappend -T 10 -K secret -A -D Alice -R 1 -F log1

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
