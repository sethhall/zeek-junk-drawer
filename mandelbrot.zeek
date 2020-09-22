
const stdout = open("/dev/stdout") &raw_output;


const WIDTH = 80;
const HEIGHT = 25;
#const output_chars = vector(" ", "\x25\x91");

#const characters = vector(" ", ".", ":", "-", "#", "o", "*", ">");#, ")", #, "|", "&", "I", "H", "%", "*", "#");
const characters = " .:-#o*>";
function CalculateRow(y: double, factor: double, shiftRight: double)
	{
	local output: vector of string = vector();
	local XCenter = -0.45;
	local XStep = 0.3;
	local MaxIterations = 50;

	local xLines = WIDTH - 2;
	local xMin = XCenter - xLines / 2.0 * XStep;
	local xMax = XCenter + xLines / 2.0 * XStep;

	local xCoords: vector of double = vector();
	local xtmp = xMin * factor + shiftRight;
	while ( xtmp <= xMax * factor + shiftRight )
		{
		xCoords += xtmp;
		xtmp += XStep * factor;
		}

	local i = 0;
	while ( ++i < |xCoords| )
		{
		local x = xCoords[i];
		local iterations = 0;
		local xTemp = x;
		local yTemp = y;
		local arg = x*x + y*y;
		while ( arg < |characters| && iterations < |characters| * MaxIterations )
			{
			local xSqr = xTemp * xTemp;
			local ySqr = yTemp * yTemp;

			yTemp = 2 * xTemp * yTemp - y;
			xTemp = xSqr - ySqr - x;
			
			arg = xSqr + ySqr;
			++iterations;
			}

		# Build up the full row
		#output += characters[iterations % |characters|];
		print stdout, characters[iterations % |characters|];
		}
	
	print stdout, "\n";
	#return join_string_vec(output, "");
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
	local yLines = HEIGHT;
	
	local yMin = YCenter - (yLines / 2.0) * YStep;
	local yMax = YCenter + (yLines / 2.0) * YStep;
	
	while (zoomFactor > StopfactorZoom)
		{
		local shiftRight = zoomFactor > StopfactorShr ? zoomFactor / ZoomSpeed : StopfactorShr;
		local shiftUp = zoomFactor > StopfactorShu ? zoomFactor / ZoomSpeed : StopfactorShu;

		local yCoords: vector of double = vector();
		local y = yMax * zoomFactor - shiftUp;
		while ( y >= yMin * zoomFactor - shiftUp )
			{
			yCoords += y;
			y -= YStep * zoomFactor;
			}

		local i = 0;
		local tempFactor = zoomFactor;
		while ( ++i < |yCoords| )
			{
			#print CalculateRow(yCoords[i], tempFactor, shiftRight);
			CalculateRow(yCoords[i], tempFactor, shiftRight);
			}

		zoomFactor = zoomFactor * ZoomSpeed;

		# Reset the cursor to the zero position but don't clear
		# the screen.  Clearing the screen gives a tearing effect.
		print stdout, "\n\x1b[0;0H";
		}
	}

event zeek_init()
	{
	# Clear the screen.
	print stdout, "\x1bc";
	draw_fractal();
	}	
