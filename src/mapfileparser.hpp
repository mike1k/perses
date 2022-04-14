#pragma once

namespace perses
{
	struct MapSymbol
	{
		u32 sectionIndex;
		u32 sectionOffset;
		u64 address;
		std::string name;
		std::string libobj;
	};

	enum class MapFileType
	{
		kIDAPro = 0,
		kMSVC,
		kLLVM
	};

	class MapFileParser : pe::msc::NonCopyable
	{
	public:
		virtual ~MapFileParser() = default;

		bool parse(std::filesystem::path filePath);
		
		const std::vector<MapSymbol>& getSymbols() const {
			return _symbols;
		}
	protected:
		MapFileParser() = default;
		virtual bool parseLine(std::string_view line) = 0;
	protected:
		std::vector<MapSymbol>	_symbols;
	};

	class MSVCMapFileParser : public MapFileParser
	{
	public:
		MSVCMapFileParser() {}

	protected:
		bool parseLine(std::string_view line) override;
	};

	class IDAMapFileParser : public MapFileParser
	{
	public:
		IDAMapFileParser() {}

	protected:
		bool parseLine(std::string_view line) override;
	};
}