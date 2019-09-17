#!/bin/bash

#FILE_PATH = $1
awk 'BEGIN{n=0; sum=0}{sum=sum+$1; n++; print "20 " sum " " n " "  sum/n*1000;}' $1
