#pragma once

namespace perses
{
	template<int BitSize = 32>
	class X86BinaryApplication
	{
	public:
		X86BinaryApplication() = delete;
		X86BinaryApplication(std::string_view filePath);
		~X86BinaryApplication();

		void loadFromFile(std::string_view filePath);
		SharedProtectionSchema buildSchema(int flag);
		bool scanForMarkers();
		bool addRoutineByAddress(uptr address, int marker);
		bool addRoutineBySymbol(std::string_view symbolName, int marker);
		bool addRoutineBySymbol(const MapSymbol* symbol, int marker);
		bool addRoutineByAddress(uptr start, uptr end, int marker);
		bool transformRoutines();
		bool isRelocationPresent(u32 rva);
		void removeRelocation(u32 rva);
		void dumpRoutines();
		void linkCode(Routine* origRtn, assembler::CodeHolder& code, const std::vector<RelocationEntry>& relocs, const std::vector<JumpTableEntry>& jumpTable);
		void compile(std::string_view sectionName = ".perses");
		bool linkMapFile(MapFileType type, std::filesystem::path filePath);
		bool hasMapFile() const;
		bool inquireJumpTable(instruction_t* insn, uptr begin, uptr end, int entryCount, std::vector<JumpTableEntry>& entries);
		bool parseFunctionList(std::filesystem::path path);
		assembler::Environment getEnvironment();

		uptr getBaseAddress() { return _peFile.getImageBase(); }
		pe::Image<BitSize>& getImage() { return _peFile; }
		std::vector<MapSymbol>& getSymbols() { return _mapSymbols; }
		const std::vector<Routine>& getRoutines() const { return _routines; }
		const std::set<u32>& getOriginalRelocs() const { return _originalRelocs; }
	private:
		std::vector<Routine>				_routines;
		std::map<uptr, std::pair<uptr, pepp::mem::ByteVector>> _proutines;
		pe::Image<BitSize>					_peFile;
		std::set<u32>						_originalRelocs;
		std::vector<RelocationEntry>		_newRelocs;
		std::map<u32, std::vector<RelocationEntry>> _relocBlocks;
		size_t								_currentSectionOffset{};
		std::filesystem::path				_filePath;
		std::vector<MapSymbol>				_mapSymbols;
		std::vector<MapSymbol>				_mapFuncSymbols;
		MapFileType							_mapType;
		uptr								_persesAddr{};
	};
}