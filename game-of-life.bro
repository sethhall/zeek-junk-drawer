##! Conway's Game of Life implemented in the Bro programming language.
##!
##! Author: Seth Hall <seth@icir.org>

@load frameworks/communication/listen

module ConwaysGameOfLife;

export {
	## The length of time between each generation.
	const generation_life = .1sec &redef;
}

type Field: record {
	field: vector of bool;
	seed_field: vector of bool &optional;
	generation: count &default=0;
	x: count;
	y: count;
};

const iter3=set(-1,0,1);
const looper="this is an arbitrary string that is used for looping. it just needs to be nice and long to accomodate the maximum length someone might use on an axis of their field.";

function draw_field(f: Field)
	{
	print fmt("====Generation: %d====", f$generation);

	local i = 0;
	for ( y in looper )
		{
		local j = 0;
		local field_line="";
		for ( x in looper )
			{
			local cell = f$x*i+j;
			field_line += (f$field[cell]) ? "X" : ".";
			if ( ++j == f$x )
				break;
			}
		print field_line;
		if ( ++i == f$y )
			break;
		}
	}

function count_alive(f: Field, i: count, j: count): count
	{
	local ret=0;

	for ( a in iter3 )
		{
		local x: int = i+a;
		for ( b in iter3 )
			{
			local y: int = j+b;
			if ( x==i && y==j )
				next;
			if ( y < f$y && x < f$x &&
			     x >= 0 && y >= 0)
				{
				ret += f$field[f$x*y+x] ? 1:0;
				}
			}
		}
	return ret;
	}

function evolve(f: Field): Field
	{
	local i = 0;
	local alive = 0;
	local tmp_field = copy(f$field);
	for ( x in looper )
		{
		local j = 0;
		for ( y in looper )
			{
			alive = count_alive(f, i, j);
			local cell = f$x*j+i;
			local cs = f$field[cell];
			if ( cs )
				{
				if ( (alive > 3) || ( alive < 2 ) )
					tmp_field[cell] = F;
				else
					tmp_field[cell] = T;
				} 
			else 
				{
				if ( alive == 3 )
					tmp_field[cell] = T;
				else
					tmp_field[cell] = F;
				}
			++j;
			if ( j == f$y )
				break;
			}
		++i;
		if ( i == f$x )
			break;
		}
	f$field = tmp_field;
	return f;
	}

event loop_event(f: Field)
	{
	draw_field(f);
	++f$generation;
	if ( !any_set(f$field) )
		print "Extinction!";
	else
		schedule generation_life { loop_event(evolve(f)) };
	}

function run(f: Field)
	{
	if ( f$x*f$y != |f$field| )
		{
		Reporter::error("Your 'Game of Life' field is not laid out correctly.");
		return;
		}

	f$seed_field = copy(f$field);
	event loop_event(f);
	}

event bro_init()
	{
	local data = vector(F,F,F,T,F,T,T,F,T,F,T,F,T,
	                    T,F,T,F,F,F,F,F,F,T,F,T,T,
	                    F,F,F,T,F,T,F,F,T,T,T,T,T,
	                    F,F,T,F,T,T,F,F,F,F,T,F,F,
	                    T,F,F,F,F,T,T,F,T,F,F,F,F,
	                    T,F,F,F,T,T,F,F,F,T,F,T,T,
	                    F,F,F,F,F,F,T,F,T,F,F,F,T,
	                    F,F,F,T,F,F,F,F,T,F,T,F,F,
	                    F,F,F,F,F,T,T,F,F,T,F,T,F);
	ConwaysGameOfLife::run([$field=data, $x=13, $y=9]);
	}
