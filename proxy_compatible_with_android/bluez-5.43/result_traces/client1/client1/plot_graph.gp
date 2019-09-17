#!/usr/bin/gnuplot
set key font "Helvetica,12"
set key at 37,190
#set key at 100,150
#set key right bottom
set xlabel "IP network Round Trip Time, [ms]"
set ylabel "Connection delay, [ms]"
set style line 1 lt 1 lc rgb "#8B0000" lw 3 pt 5 ps 1.3
set style line 2 lt 1 lc rgb "#006400" lw 3 pt 7 ps 1.3
set style line 3 lt 2 dt 2 lc rgb "#1E90FF" lw 3 pt 13 ps 1.3
set style line 4 lt 2 dt 2 lc rgb "#FF4500" lw 3 pt 9 ps 1.3
plot "new_connection_delay" u 1:3 w lp ls 1 title 'C_1'
replot "../../client2/client2/connection_delay_c2_delayed" u 1:2 w lp ls 2 title 'C_2'
replot "../../server/new_connection_delay_c1" u 1:2 w lp ls 3 title 'S_{C_1,P}'
replot "../../server/connection_delay_c2" u 1:2 w lp ls 4 title 'S_{C_2,P}'
#set term postscript enhanced color 'Helvetica,30' background rgb 'white'
set term postscript enhanced color 'Helvetica,14' size 5in,3.7in
set output 'connection_delay.eps'
replot
