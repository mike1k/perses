#include "perses.hpp"
#include <regex>

using namespace perses;

bool MapFileParser::parse(std::filesystem::path filePath)
{
	if (!std::filesystem::exists(filePath))
		return false;

	std::ifstream infile(filePath);
	std::string line;

	while (std::getline(infile, line))
	{
		parseLine(line);
	}

	return !_symbols.empty();
}

bool MSVCMapFileParser::parseLine(std::string_view line)
{
	std::string s = line.data();
	std::regex rgx (R"#(\s(\d+)\:([a-fA-F0-9]+)\s+(\S+)\s+([a-fA-F0-9]+)\s+(.+))#", std::regex_constants::ECMAScript);

	if (std::regex_match(s, rgx))
	{
		for (std::smatch m; std::regex_search(s, m, rgx); s = m.suffix())
		{
			MapSymbol symbol { };

			symbol.address = std::strtoull(m[4].str().c_str(), nullptr, 16);

			if (symbol.address == 0ull)
				continue;

			symbol.sectionIndex = std::atoi(m[1].str().c_str());
			symbol.sectionOffset = std::strtoul(m[2].str().c_str(), nullptr, 16);
			symbol.name = m[3].str();
			symbol.libobj = m[5].str();

			_symbols.emplace_back(std::move(symbol));
		}

		return true;
	}

	return false;
}

bool IDAMapFileParser::parseLine(std::string_view line)
{
	std::string s = line.data();
	std::regex rgx(R"#(.(\d+)\:([a-fA-F0-9]+)\s+(\S+))#", std::regex_constants::ECMAScript);

	if (std::regex_match(s, rgx))
	{
		for (std::smatch m; std::regex_search(s, m, rgx); s = m.suffix())
		{
			MapSymbol symbol{ };

			symbol.address = 0ull;
			symbol.sectionIndex = std::atoi(m[1].str().c_str());
			symbol.sectionOffset = std::strtoul(m[2].str().c_str(), nullptr, 16);
			symbol.name = m[3].str();

			_symbols.emplace_back(std::move(symbol));
		}

		return true;
	}

	return false;
}