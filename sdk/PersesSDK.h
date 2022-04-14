#pragma once

#include <intrin.h>
#include <intrin0.h>

#define PERSES_MUTATION_START() \
{\
	__nop();\
	__nop();\
	__debugbreak();\
	__debugbreak();\
	_disable();\
}

#define PERSES_MUTATION_END() \
{\
	_enable();\
	__debugbreak();\
	__debugbreak();\
	__nop();\
	__nop();\
}