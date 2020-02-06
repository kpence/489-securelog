#!/bin/bash


openssl enc -aes-256-cbc -in plaintext1.txt -out test1.txt -base64 -md sha1
openssl enc -aes-256-cbc -in plaintext2.txt -out test2.txt -base64 -md sha1
openssl enc -aes-256-cbc -in plaintext3.txt -out test3.txt -base64 -md sha1
