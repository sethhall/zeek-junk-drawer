@load ./exec


event bro_init()
	{
	when ( local result = Exec::run([$cmd="ls /", $read_files=set("/blah.txt")]) )
		{
		print "it ran?!?";
		if ( result?$stdout )
			print result$stdout;
		if ( result?$files )
			print result$files;
		}
	}

