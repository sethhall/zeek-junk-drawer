@load ./exec

event bro_init()
	{
	Exec::run("ls /", function(r: Exec::Result)
		{
		if ( ! r?$stdout )
			{
			print "nothing?!?";
			return;
			}

		for ( i in r$stdout ) 
			{
			print r$stdout[i];
			}
		});
	}

