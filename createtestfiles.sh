#!/bin/bash


echo "THE KEY IS GREAT" > signature.txt

openssl enc -A -aes-256-cbc -in signature.txt -out encsig.txt -base64 -md sha1
#openssl enc -A -aes-256-cbc -in plaintext1.txt -out test1.txt -base64 -md sha1
#openssl enc -A -aes-256-cbc -in plaintext1.txt -out test2.txt -base64 -md sha1

#cat encsig.txt test1.txt test2.txt > output.txt
#cat encsig.txt test1.txt > output.txt
cat encsig.txt > output.txt
