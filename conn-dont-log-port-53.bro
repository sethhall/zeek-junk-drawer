
@load base/protocols/conn

event bro_init()
	{
	local filt = Log::get_filter(Conn::LOG, "default");
	filt$pred = function(rec: Conn::Info): bool
		{
		return ( rec$id$resp_p != 53/udp && rec$id$resp_p != 53/tcp );
		};
	Log::add_filter(Conn::LOG, filt);
	}