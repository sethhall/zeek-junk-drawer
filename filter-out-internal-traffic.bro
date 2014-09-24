@load base/frameworks/packet-filter
@load base/utils/site

event bro_init() &priority=5
	{
	local nets = "";
	for ( network in Site::local_nets )
		{
		if ( nets != "" )
			nets += " or ";

		nets += cat(network);
		}
	restrict_filters["no-internal"] = fmt("not ( src net (%s) and dst net (%s) )", nets, nets);
	}