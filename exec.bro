
module Exec;

export {
	type Command: record {
		cmd:         string;
		stdin:       string      &default="";
		read_files:  set[string] &optional;
	};

	type Result: record {
		exit_code:    count            &default=0;
		stdout:       vector of string &optional;
		stderr:       vector of string &optional;
		files:        table[string] of vector of string &optional;
	};

	global run: function(cmd: Command): Result;
}

redef record Command += {
	# The prefix name for tracking temp files.
	prefix_name: string &optional;
};

global results: table[string] of Result = table();
global finished_commands: set[string];
#global callbacks: table[string] of function(r: Result);

type OneLine: record { line: string; };

event Exec::stdout_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	local result = results[name];
	if ( ! results[name]?$stdout )
		result$stdout = vector(s);
	else
		result$stdout[|result$stdout|] = s;
	}

event Exec::stderr_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	local result = results[name];
	if ( ! results[name]?$stderr )
		result$stderr = vector(s);
	else
		result$stderr[|result$stderr|] = s;
	}

event Exec::file_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local parts = split1(description$name, /_/);
	local name = parts[1];
	local track_file = parts[2];

	local result = results[name];
	if ( ! result?$files )
		result$files = table();
	
	if ( track_file !in result$files )
		result$files[track_file] = vector(s);
	else
		result$files[track_file][|result$files[track_file]|] = s;
	}

event Exec::cleanup_and_do_callback(name: string)
	{
	Input::remove(fmt("%s_stdout", name));
	system(fmt("rm %s_stdout", name));

	Input::remove(fmt("%s_stderr", name));
	system(fmt("rm %s_stderr", name));

	Input::remove(fmt("%s_done", name));
	system(fmt("rm %s_done", name));

	#callbacks[name](results[name]);
	#delete callbacks[name];
	#delete results[name];

	# Indicate to the "when" async watcher that this command is done.
	add finished_commands[name];
	}

event Exec::run_done(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	if ( /^exit_code:/ in s )
		results[name]$exit_code = to_count(split1(s, /:/)[2]);
	else if ( s == "done" )
		schedule 1sec { Exec::cleanup_and_do_callback(name) };
	}

event Exec::start_watching_files(cmd: Command)
	{
	Input::add_event([$source=fmt("%s_done", cmd$prefix_name),
	                  $name=fmt("%s_done", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::run_done]);

	Input::add_event([$source=fmt("%s_stdout", cmd$prefix_name),
	                  $name=fmt("%s_stdout", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stdout_line]);

	Input::add_event([$source=fmt("%s_stderr", cmd$prefix_name),
	                  $name=fmt("%s_stderr", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stderr_line]);

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			Input::add_event([$source=fmt("%s", read_file),
			                  $name=fmt("%s_%s", cmd$prefix_name, read_file),
			                  $reader=Input::READER_RAW,
			                  $mode=Input::STREAM,
			                  $want_record=F,
			                  $fields=OneLine,
			                  $ev=Exec::file_line]);
			}
		}
	}

function run(cmd: Command): Result
	{
	print "entering the async whatever";

	cmd$prefix_name = "/tmp/bro-exec-" + unique_id("");
	system(fmt("touch %s_done", cmd$prefix_name));
	system(fmt("touch %s_stdout", cmd$prefix_name));
	system(fmt("touch %s_stderr", cmd$prefix_name));
	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			system(fmt("touch %s 2>/dev/null", read_file));
		}

	# Sleep for 1 sec before writing to the done file to avoid race conditions
	# This makes sure that all of the data is read from 
	piped_exec(fmt("%s 2>> %s_stderr 1>> %s_stdout; echo \"exit_code:${?}\" >> %s_done; echo \"done\" >> %s_done", 
	               cmd$cmd, cmd$prefix_name, cmd$prefix_name, cmd$prefix_name, cmd$prefix_name),
	           cmd$stdin);

	results[cmd$prefix_name] = [];
	#callbacks[cmd$prefix_name] = cb;

	schedule 1msec { Exec::start_watching_files(cmd) };

	return when ( cmd$prefix_name in finished_commands )
		{
		print "yay!";
		print results;
		#return results[cmd$prefix_name];
		#delete finished_commands[cmd$prefix_name];
		#local result = results[cmd$prefix_name];
		#delete results[cmd$prefix_name];
		#return result;
		}
	}

