#!/bin/bash

#FILE_PATH = $1
#awk 'BEGIN{n=0; sum=0; delay=0}{sum=sum+$2; n++; print delay " " sum " " n " "  sum/n; delay=delay+10;}END{for(i=0; i<=100; i=i+10) print i " " sum/n}' $1
awk 'BEGIN{n=0; sum=0;}{sum=sum+$2; n++;}END{for(i=0; i<=100; i=i+10) print i " " sum/n}' $1
