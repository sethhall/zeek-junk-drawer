
module NTPLier;

export {
	
}

const ports = {
	123/udp, 123/tcp
};
redef likely_server_ports += { ports };

# Initialize the HTTP logging stream and ports.
event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	}

event ntp_message(u: connection, msg: ntp_msg, excess: string)
	{
	local now = network_time();
	local diff = ( now > msg$xmit_t ) ? (now - msg$xmit_t) : (msg$xmit_t - now); 

	if ( msg$stratum > 0 && diff > 2.0secs )
		{
		print network_time();
		print msg;
		print u$id;
		print "";
		}
	}