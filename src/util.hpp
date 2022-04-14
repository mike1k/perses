#pragma once

#include <random>

static std::default_random_engine rng;

namespace perses::util
{
	template<typename _Ty>
	_Ty genRandInteger() 
	{
		std::random_device r;
		std::default_random_engine e1(r());
		std::uniform_int_distribution<_Ty> dist;
		return dist(e1);
	}

	template<typename _Ty>
	_Ty genRandInteger(_Ty min, _Ty max)
	{
		std::random_device r;
		std::default_random_engine e1(r());
		std::uniform_int_distribution<_Ty> dist(min, max);
		return dist(e1);
	}
}