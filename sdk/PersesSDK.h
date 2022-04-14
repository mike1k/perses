#pragma once

#include <intrin.h>
#include <intrin0.h>

#define PERSES_MUTATION_START() \
{\
	__debugbreak();\
	__debugbreak();\
	__nop();\
	__nop();\
	_disable();\
}

#define PERSES_MUTATION_END() \
{\
	_enable();\
	__nop();\
	__nop();\
	__debugbreak();\
	__debugbreak();\
}
