
const stdout = open("/dev/stdout") &raw_output;
const stderr = open("/dev/stderr") &raw_output;


const WIDTH = 500.0;
const HEIGHT = 500.0;

const colors = string_vec("0 0 0",
               "255   0   0",
               "  0 255   0",
              "  0   0 255",
               "255 255   0",
               "255 255 255",
               "255   0   0") &redef;

#const colors = "1234567890123456";

                      

function CalculateRow(image: string_vec, y: double, factor: double, shiftRight: double)
	{
	local output: vector of string = vector();
	local XCenter = -0.45;
	local XStep = 0.3;
	local MaxIterations = 50.0;

	local xMin = XCenter - (WIDTH / 2.0 * XStep);
	local xMax = XCenter + (WIDTH / 2.0 * XStep);
#print stderr, fmt("xmin: %f  xmax: %f\n", xMin, xMax);

	local xCoords: vector of double = vector();
	local xtmp = xMin * factor + shiftRight;
	while ( xtmp <= xMax * factor + shiftRight && |xCoords| != WIDTH )
		{
		xCoords += xtmp;
		xtmp += XStep * factor;
		}

#print stderr, fmt("xcoords: %d\n", |xCoords|);
#print stderr, fmt("xcoords: %s\n", cat(xCoords));

	local i = 0;
	while ( ++i < |xCoords| )
		{
		local x = xCoords[i];
		local iterations = 0;
		local xTemp = x;
		local yTemp = y;
		local arg = x*x + y*y;
		while ( arg < |colors| && iterations < |colors| * MaxIterations )
		#while ( arg < |colors| && iterations < MaxIterations )
			{
			local xSqr = xTemp * xTemp;
			local ySqr = yTemp * yTemp;

			yTemp = 2.0 * xTemp * yTemp - y;
			xTemp = xSqr - ySqr - x;
			
			arg = xSqr + ySqr;
			++iterations;
			}

		# Build up the full row
		image += colors[iterations % |colors|];
		#image += fmt("%d", (iterations % |colors|));
		}
	
	image += "\n";
	}


function draw_fractal()
	{
	local StopfactorZoom = 0.00000000000005;
	local StopfactorShr = 0.7496494959997;
	local StopfactorShu = 0.03000094443895;
	local ZoomSpeed = 0.95;
	local YCenter = 0.95;
	local YStep = 0.5;

	local zoomFactor = 0.9;
	
	local yMin = YCenter - (HEIGHT / 2.0 * YStep);
	local yMax = YCenter + (HEIGHT / 2.0 * YStep);
	
	while (zoomFactor > StopfactorZoom)
		{
		print stdout, "\033]1337;File=inline=1:";
		local image = string_vec();
		image += "P3\n";
		image += fmt("%d %d\n", double_to_count(WIDTH-1), double_to_count(HEIGHT-1));
		image += fmt("%d\n", |colors|);

		local shiftRight = zoomFactor > StopfactorShr ? zoomFactor / ZoomSpeed : StopfactorShr;
		local shiftUp = zoomFactor > StopfactorShu ? zoomFactor / ZoomSpeed : StopfactorShu;

		local yCoords: vector of double = vector();
		local y = yMax * zoomFactor - shiftUp;
		while ( y >= yMin * zoomFactor - shiftUp && |yCoords| != HEIGHT )
			{
			yCoords += y;
			y -= YStep * zoomFactor;
			}

		local i = 0;
		local tempFactor = zoomFactor;

#print stderr, fmt("ycoords: %d\n", |yCoords|);
		while ( ++i < |yCoords| )
			{
			CalculateRow(image, yCoords[i], tempFactor, shiftRight);
			}

		print stdout, encode_base64(join_string_vec(image, " "));
		print stdout, "\a\n";
#print "------";
#print stdout, join_string_vec(image, " ");
#flush_all();
#print "------";
#		exit(1);

		zoomFactor = zoomFactor * ZoomSpeed;

		# Reset the cursor to the zero position but don't clear
		# the screen.  Clearing the screen gives a tearing effect.
		#print stdout, "\n\x1b[0;0H";
		
#		print stdout, "\x1bc";
		}
	}

event zeek_init()
	{
	# Clear the screen.
	#print stdout, "\x1bc";
	draw_fractal();
	}
