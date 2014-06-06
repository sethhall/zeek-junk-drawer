@load ./brainfuck

redef exit_only_after_terminate=T;

event bro_init()
	{
	local hello_world = "++++++++++ [ >+++++++ >++++++++++ >+++ >+ <<<<- ] >++.>+. +++++++. . +++. >++. <<+++++++++++++++. >. +++. ------. --------. >+. >.";
	BrainFuck::run(hello_world);
	}