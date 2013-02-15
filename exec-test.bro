@load ./exec

event blah()
	{
	when ( local result = Exec::run([$cmd="ls /", $read_files=set("/blah.txt")]) )
		{
		print "it ran?!?";
		if ( result?$stdout )
			print result$stdout;
		}
		
	}

event bro_init()
	{
	event blah();
	}

