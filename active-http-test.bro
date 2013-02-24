
event bro_init()
	{
	when ( local resp = ActiveHTTP::request([$url="http://www.iscomputeron.com/"]) )
		{
		print resp;
		}
	}