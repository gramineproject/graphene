#!/bin/bash

sudo service aesmd stop
sudo rmmod graphene_sgx
sudo rmmod isgx
make || exit -1
sudo modprobe isgx || exit -1
sudo insmod graphene-sgx.ko || exit -1
sudo service aesmd start || exit -1
