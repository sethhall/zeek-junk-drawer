
@load base/utils/site
@load base/frameworks/sumstats

@load ./domain-tld

module Top;

export {
	## How many of the top missing names should be logged.
	const top_k = 10 &redef;

	## How often the log should be written.
	const logging_interval = 15mins &redef;

	## The records that should be tracked and logged.
	const records: set[string] = {
		"A",
		"AAAA",
		"CNAME",
	} &redef;

	## The log ID.
	redef enum Log::ID += { DNS_LOG };

	type Info: record {
		ts:           time             &log;
		ts_delta:     interval         &log;
		record_type:  string           &log;
		top_queries:  vector of string &log;
		top_counts:   vector of string &log;
		top_epsilons: vector of string &log;
	};
}

event bro_init() &priority=5
	{
	Log::create_stream(DNS_LOG, [$columns=Info]);

	local r1 = SumStats::Reducer($stream="domain trimmed dns", 
	                             $apply=set(SumStats::TOPK), 
	                             $topk_size=top_k*10);
	SumStats::create([$name="find-top-queries",
	                  $epoch=logging_interval,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["domain trimmed dns"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, top_k);

	                  	local top_queries = string_vec();
	                  	local top_counts = index_vec();
	                  	local top_epsilons = index_vec();
	                  	local i = 0;
	                  	for ( element in s ) 
	                  		{
	                  		top_queries[|top_queries|] = s[element]$str;
	                  		top_counts[|top_counts|] = topk_count(r$topk, s[element]);
	                  		top_epsilons[|top_epsilons|] = topk_epsilon(r$topk, s[element]);

	                  		if ( ++i == top_k )
	                  			break;
	                  		}

	                  	Log::write(DNS_LOG, [$ts=ts, 
	                  	                 $ts_delta=logging_interval, 
	                  	                 $record_type=key$str,
	                  	                 $top_queries=top_queries, 
	                  	                 $top_counts=top_counts, 
	                  	                 $top_epsilons=top_epsilons]);
	                  	}
	                 ]);
	}

event DNS::log_dns(rec: DNS::Info)
	{
	if ( rec?$query && rec?$qtype &&
	     rec$qtype_name in records &&
	     ! Site::is_local_name(rec$query) )
		{
		local trimmed_query = DomainTLD::effective_domain(rec$query);
		SumStats::observe("domain trimmed dns", [$str=rec$qtype_name], [$str=trimmed_query]);
		}
	}
