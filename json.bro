@load base/utils/strings

module JSON;

export {
	## A function to convert arbitrary Bro data into a JSON string.
	##
	## v: The value to convert to JSON.  Typically a record.
	##
	## only_loggable: If the v value is a record this will only cause
	##                fields with the &log attribute to be included in the JSON.
	##
	## returns: a JSON formatted string.
	global convert: function(v: any, only_loggable: bool &default=F): string;
}

function convert(v: any, only_loggable: bool &default=F): string
	{
	local tn = type_name(v);
	switch ( tn )
		{
		case "type":
		return "";

		case "string":
		return cat("\"", gsub(gsub(clean(v), /\\/, "\\\\"), /\"/, "\\\""), "\"");

		case "addr":
		fallthrough;
		case "port":
		return cat("\"", v, "\"");

		case "int":
		fallthrough;
		case "count":
		fallthrough;
		case "time":
		fallthrough;
		case "double":
		fallthrough;
		case "bool":
		fallthrough;
		case "enum":
		return cat(v);

		default:
		break;
		}

	if ( /^record/ in tn )
		{
		local rec_parts: set[string] = set();

		local ft = record_fields(v);
		for ( field in ft )
			{
			local field_desc = ft[field];
			if ( field_desc?$value && (!only_loggable || field_desc$log) )
				{
				local onepart = cat("\"", field, "\": ", JSON::convert(field_desc$value, only_loggable));
				add rec_parts[onepart];
				}
			}
			return cat("{", join_string_set(rec_parts, ", "), "}");
		}
	
	# None of the following are supported.
	else if ( /^set/ in tn )
		{
		return "[]";
		}
	else if ( /^table/ in tn )
		{
		return "[]";
		}
	else if ( /^vector/ in tn )
		{
		return "[]";
		}
	
	return "\"\"";
	}
