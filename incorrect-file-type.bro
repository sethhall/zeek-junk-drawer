
module IncorrectFileType;

export {
	redef enum Notice::Type += { 
		## Discovery of an incorrect file type.
		Found
	};

	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	local fname = f$info?$filename ? f$info$filename : Files::describe(f);
	if ( f?$mime_type && 
	     f$mime_type in mime_types_extensions &&
	     mime_types_extensions[f$mime_type] !in fname )
		{
		local message = fmt("Filename (%s) doesn't match filetype (%s)", fname, f$mime_type);
		NOTICE([$note=Found,
		        $msg=message,
		        $sub=Files::describe(f),
		        $conn=c]);
		}
	}