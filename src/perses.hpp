#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <string_view>
#include <map>
#include <filesystem>
#include <set>

// - X86 code assembling engine
#include <asmjit/asmjit.h>

// - X86 disassembler
#include <Zydis/Zydis.h>

// - PE (Portable Executable) library for parsing and manipulation.
#include <pepp/PELibrary.hpp>

// - Logging library
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/stopwatch.h>
#include <spdlog/fmt/bin_to_hex.h>

// - Additional utilities
#include "details.hpp"
#include "disasm.hpp"
#include "util.hpp"
#include "MapFileParser.hpp"
#include "x86util.hpp"
#include "x86application.hpp"
#include "protectionschema.hpp"

std::shared_ptr<spdlog::logger> logger();