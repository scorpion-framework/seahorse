module seahorse.util;

import std.conv : to;

import scorpion.config : parseProperties;

enum prop(string file) = parseProperties(import(file));

T get(T)(string[string] config, string key, T defaultValue) {
	auto ret = key in config;
	if(ret) return to!T(*ret);
	else return defaultValue;
}
