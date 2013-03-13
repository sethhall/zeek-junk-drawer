@load ./dir

event bro_init()
	{
	Dir::monitor("/", function(fname: string)
		{
		print fname;
		});
	}

