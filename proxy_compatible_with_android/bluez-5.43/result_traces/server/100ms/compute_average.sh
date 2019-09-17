#!/bin/bash

#DELAY = $1
awk 'BEGIN{n=0; sum=0}{sum = sum + $1; n++;}END{print "100 "  sum/n*1000}' delays_c1 >> ../connection_delay_c1
awk 'BEGIN{n=0; sum=0}{sum = sum + $1; n++;}END{print "100 "  sum/n*1000}' delays_c2 >> ../connection_delay_c2
