<div align="center">
  <img src="https://i.imgur.com/Yi2ya5f.png" width="75%" height="75%">
</div>

# Introduction

PERSES is a X86 code obfuscation engine that works with [Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable) files. The obfuscation works by replacing a specific instruction with a larger more sophisticated set that is semantically compatible to the original. PERSES only mutates 4 instructions yet has adverse effects on analyzers/decompilers due to the method of mutation. For more information on PERSES' inner workings, please check out the article written [here](https://back.engineering/13/04/2022/). 

PERSES is a work in progress and does not attempt to be a replacement for any established code obfuscation engine, so please be mindful when using it to protect your code. Furthermore, X64 support can be slightly improved and augmented to ensure semantical accuracy.

# Reference Manual

PERSES by default works off a command line. Listed below are the arguments requried to utilize PERSES.

| Argument           	| Description                                                                                                                                                               	| May Require        	|
|--------------------	|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|--------------------	|
| `-f` or `--file`   	| Path to the input PE file.                                                                                                                                                	| :heavy_check_mark: 	|
| `-a` or `-address` 	| Address or list of addresses required to be mutated.                                                                                                                      	| :heavy_check_mark: 	|
| `-s` or `--symbol` 	| Symbol or list of symbols to be mutated. This requires a linked `.map` file.                                                                                              	| :x:                	|
| `--map`            	| Map file to be linked. IDA Pro `.map` files must have their extension replaced with `.ida`.                                                                               	| :x:                	|
| `--list`           	| List of functions to be mutated. Each entry must envelop one line and be formatted as `0x1000:0x2000` where `0x1000` is the start and `0x2000` is the end of the routine. 	| :x:                	|
| `--x64`            	| Used to indicate that the file is of 64bit architecture (AMD64).                                                                                                          	| :heavy_check_mark: 	|
| `--rets`           	| Allow PERSES to build a `RET` gadget pool used to create `JMP`s to random locations.                                                                                      	| :x:                	|
| `--scan`           	| Force PERSES to scan for code protection markers.                                                                                                                         	| :x:                	|

Both symbols and addresses can be used, but atleast one of them must be present.

> :information_source:  Due to limitations in the `argparse` library, if more than one address or symbol are required, please append the `-a` or `-s` argument and parameters last.


## Working with PERSES Manually

If desired, PERSES can be used manually to generate mutated binaries. To begin, one must declare a `X86BinaryApplication` instance with the provided template parameter.

* `X86BinaryApplication<PERSES_64BIT>(filepath)` to generate a `X86_64` instance.
* `X86BinaryApplication<PERSES_32BIT>(filepath)` to generate a `X86` instance.

### RET Gadgets

After instantiating the object, the `RET` gadget pool mentioned above can be optionally created with `perses::buildKnownRetGadgets(app)`. 

### MAP Files

MAP files are optionally produced by compilers to show symbols and sections present in a binary with their corresponding address. PERSES allows MAP files from `IDA Pro` and `MSVC` (tested on VS2022) to be linked via `X86BinaryApplication::linkMapFile`. Afterwards, symbols can be traversed via `X86BinaryApplication::getSymbols` or added directly into the mutation queue by calling `addRoutineBySymbol`. For instance, after linking the map file, adding `main` to the mutation queue is as simple as:

```cpp
app->addRoutineBySymbol("main", PERSES_MARKER_MUTATION);
```

MAP files can aid function size calculation by exposing known symbols, however, MAP linking is completely optional and only added as a convenience.

### Function Lists

If mutating a batch of functions is wanted, function lists can be parsed in order to add the specified routines automatically. This is done by calling `parseFunctionList`. Please be mindful of the required format listed [above](#Reference-Manual) in the argument table. Futhermore, the end address supplied is expected to be the end of a function, providing anything else will likely result in instability of the output program.

### Markers

The [PersesSDK](https://github.com/mike1k/perses/sdk/PersesSDK.h) can be included into a project to emit a scannable pattern into code. PERSES makes use of compiler intrinsics to generate unique patterns. Beginning and end macros named `PERSES_MUTATION_START()` and `PERSES_MUTATION_END()` are provided.

### Applying Transforms

Applying mutation on all routines in the queue is done by calling `X86BinaryApplication::transformRoutines`. Transforms are applied via the corresponding schema. At the moment, there is only one schema supplied; `MutationLight`. 

### Compiling.

Compilation of the new binary can be done with `X86BinaryApplication::compile`. PERSES creates a new file and appends `.perses` after the original filename.

# Showcase

Below are some example programs created to show the efficacy in regards to crippling decompiler output.

## Hello, world!

```cpp
int main()
{
	PERSES_MUTATION_START()

	printf("Hello, world!\n");
	Sleep(100);

	PERSES_MUTATION_END()

	return getchar();
}
```

### Output

![Output1](https://i.imgur.com/k3MvscV.png)


## Jump Table Mutation

```cpp
int main()
{
	int input = 0;

	std::cin >> input;

	switch (input)
	{
	case 0:
		std::cout << "Value is zero" << std::endl;
		break;
	case 1:
		std::cout << "Value is one" << std::endl;
		break;
	case 2:
		std::cout << "Value is two" << std::endl;
		break;
	case 3:
		std::cout << "Value is three" << std::endl;
		break;
	case 4:
		std::cout << "Value is four" << std::endl;
		break;
	default:
		std::cerr << "Unhandled value!" << std::endl;
		break;
	}

	return getchar();
}
```

> Full function mutation using command line

```
perses -f MutationTesting.exe --map MutationTesting.map --rets -s _main
```

### Output

![Output2](https://i.imgur.com/79aWu5c.png)

# Modification

Additional schemas can be created then attached to `X86BinaryApplication::buildSchema`. Alternatively, `MutationLight` can be extended as it only supports a minimal set of instructions. In order to modify the existing schema, please thoroughly read and understand [MutationLight.cpp](https://github.com/mike1k/src/MutationLight.cpp).

# Building (Windows)

PERSES utilizes [cmkr](https://github.com/build-cpp/cmkr). In order to build the PERSES project, please run the following commands:

```
git clone --recursive https://github.com/mike1k/perses.git
cmake -B build
```

# Dependencies

PERSES makes use of multiple great libraries in order to achieve it's objective. 

* [Zydis](https://github.com/zyantific/zydis)
* [AsmJit](https://github.com/asmjit/asmjit)
* [spdlog](https://github.com/gabime/spdlog)
* [argparse](https://github.com/p-ranav/argparse)
* [pepp](https://github.com/mike1k/pepp)

