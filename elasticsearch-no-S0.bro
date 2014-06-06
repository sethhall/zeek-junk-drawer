# This script prevents conn logs in state S0 from
# being logged to elasticsearch with the 
# logs-to-elasticsearch script.

@load tuning/logs-to-elasticsearch

event bro_init() &priority=-10
	{
	local filt = Log::get_filter(Conn::LOG, "default-es");

	# If there is no path_func it means that the filter
	# wasn't found (in case the conn log isn't going to ES)
	if ( ! filt?$path_func )
		return;

	Log::remove_filter(Conn::LOG, "default-es");

	filt$pred = function(rec: Conn::Info): bool 
		{
		return rec$conn_state != "S0";
		};

	Log::add_filter(Conn::LOG, filt);
	}