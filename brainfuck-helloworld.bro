@load frameworks/communication/listen
@load ./brainfuck

event bro_init()
	{
	local hello_world = "++++++++++ [ >+++++++ >++++++++++ >+++ >+ <<<<- ] >++.>+. +++++++. . +++. >++. <<+++++++++++++++. >. +++. ------. --------. >+. >.";
	BrainFuck::run(hello_world);
	}