


module Exec;

export {
	type Result: record {
		exit_code:    count            &default=0;
		stdout:       vector of string &optional;
		stderr:       vector of string &optional;
	};

	global run: function(cmd: string, cb: function(r: Result));
}

global results: table[string] of Result = table();
global callbacks: table[string] of function(r: Result);

type OneLine: record { line: string; };

event Exec::stdout_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	if ( ! results[name]?$stdout )
		results[name]$stdout = vector(s);
	else
		results[name]$stdout[|results[name]$stdout|] = s;
	}

event Exec::stderr_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	if ( ! results[name]?$stderr )
		results[name]$stderr = vector(s);
	else
		results[name]$stderr[|results[name]$stderr|] = s;
	}

event Exec::run_done(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	if ( /^exit_code:/ in s )
		{
		results[name]$exit_code = to_count(split1(s, /:/)[2]);
		}
	else if ( s == "done" )
		{
		Input::remove(fmt("%s_stdout", name));
		system(fmt("rm %s_stdout", name));

		Input::remove(fmt("%s_stderr", name));
		system(fmt("rm %s_stderr", name));

		Input::remove(fmt("%s_done", name));
		system(fmt("rm %s_done", name));

		callbacks[name](results[name]);
		delete callbacks[name];
		delete results[name];
		}
	}

event start_watching_files(name: string)
	{
	Input::add_event([$source=fmt("%s_done", name),
	                  $name=fmt("%s_done", name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::run_done]);

	Input::add_event([$source=fmt("%s_stdout", name),
	                  $name=fmt("%s_stdout", name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stdout_line]);

	Input::add_event([$source=fmt("%s_stderr", name),
	                  $name=fmt("%s_stderr", name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stderr_line]);

	}

function run(cmd: string, cb: function(r: Result))
	{
	local tmpfile = "/tmp/bro-exec-" + unique_id("");
	system(fmt("touch %s_done", tmpfile));
	system(fmt("touch %s_stdout", tmpfile));
	system(fmt("touch %s_stderr", tmpfile));
	# Sleep for 1 sec before writing to the done file to avoid race conditions
	# This makes sure that all of the data is read from 
	system(fmt("%s 2>>%s_stderr 1>> %s_stdout; echo \"exit_code:${?}\" > %s_done; sleep 1; echo \"done\" >> %s_done", cmd, tmpfile, tmpfile, tmpfile, tmpfile));

	results[tmpfile] = [];
	callbacks[tmpfile] = cb;

	schedule 1msec { start_watching_files(tmpfile) };
	}

