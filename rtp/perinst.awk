#!/usr/bin/awk -f
#code based on 
#https://github.com/vr000m/Research-Scripts/blob/aa49510d6a7c4a6b00fbde9b3dffe273f4b1e740/perinst.awk
BEGIN	{
		n=0;
		time=0.0;
		bytes=0.0;
		count = 0;
		stime=0.0
	}
	{
		if (time == 0.0) {
			stime = int($1);
			time = int($1);
		}

		if (int($1) != time) {
			printf ("%5.3f\t%5.3f\t%d\n", time-stime, bytes/125, count);
			time = int($1);
			bytes = $7;
			count = 1;
			n++;
		} else {
			time = int($1);
			bytes += $7;
			++count;
			n++;
		}
	}
END	{
	
	}