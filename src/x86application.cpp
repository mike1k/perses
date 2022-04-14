#include "perses.hpp"

using namespace perses;

// TODO: Make pepp lib. work without using templates to acknowledge PE architecture.

// Explicit templates.
template class X86BinaryApplication<PERSES_32BIT>;
template class X86BinaryApplication<PERSES_64BIT>;

#define X86BA_TEMPLATE \
template<int BitSize>

X86BA_TEMPLATE X86BinaryApplication<BitSize>::X86BinaryApplication(std::string_view filePath)
{
	loadFromFile(filePath);
}

X86BA_TEMPLATE X86BinaryApplication<BitSize>::~X86BinaryApplication()
{
}

X86BA_TEMPLATE void X86BinaryApplication<BitSize>::loadFromFile(std::string_view filePath)
{
	PERSES_THROWIFN(_peFile.setFromFilePath(filePath), "Unabled to parse the filePath, ensure this is a PE file!");

	logger()->info("Loading file in {}-bit mode: {}", BitSize, filePath.data());

	// Initialize the disassembler
	if constexpr (BitSize == PERSES_64BIT)
		Disassembler::create(ZYDIS_MACHINE_MODE_LONG_64);
	else
		Disassembler::create(ZYDIS_MACHINE_MODE_LONG_COMPAT_32);

	// Update path for compile time output.
	_filePath = filePath;

	_originalRelocs.clear();

	_peFile.getRelocDir().forEachEntry(
		[this](pe::BlockEntry const& entry)
		{
			_originalRelocs.insert(entry.getRva());
		});

	// printf("* - Number of relocations: 0x%x\n", _originalRelocs.size());
}

X86BA_TEMPLATE SharedProtectionSchema X86BinaryApplication<BitSize>::buildSchema(int flag)
{
	SharedProtectionSchema schema = nullptr;

	switch (flag)
	{
	case PERSES_MARKER_MUTATION:
		schema = ProtectionSchema::create<MutationLightSchema<BitSize>>();
		break;
	default:
		PERSES_THROW("Unknown flag passed into BinaryApplication::buildSchema.");
	}

	if (schema)
		schema->setApplication(this);

	return schema;
}

X86BA_TEMPLATE bool X86BinaryApplication<BitSize>::scanForMarkers()
{
	logger()->debug("Scanning for markers in all executable sections..");

	uptr imageBase = _peFile.getImageBase();

	for (int i = 0; i < _peFile.getNumberOfSections(); ++i)
	{
		pe::SectionHeader* sec = &_peFile.getSectionHdr(i);

		// Look for mutation macros only in executable sections
		if (sec->getCharacteristics() & pe::SCN_MEM_EXECUTE)
		{
			// Search for the known begin macro.
			for (auto& markers : MarkerTags)
			{
				if (auto matches = _peFile.findBinarySequence(sec, std::get<1>(markers)); !matches.empty())
				{
					for (u32 match : matches)
					{
						Routine rtn{ };

						u32	codeBeginOffset = match + 5;
						u32 codeSize = 0;
						u8* codeData = &_peFile.buffer()[codeBeginOffset];
						u32 codeEnd = sec->getPtrToRawData() + sec->getSizeOfRawData();

						// Continue iterating until we hit the end macro.
						while ((*(u64*)codeData & 0xffffffffffull) != std::get<2>(markers))
						{
							// Sanity check
							if ((codeBeginOffset + codeSize) >= codeEnd)
							{
								logger()->critical("Unable to find end MACRO for routine @ rva 0x{:X}",
									_peFile.getPEHdr().offsetToRva(codeBeginOffset));
								return false;
							}

							instruction_t insn{ };

							if (!Disassembler::instance()->decode(codeData, &insn))
							{
								logger()->critical("Error decoding instruction @ rva 0x{:X}",
									_peFile.getPEHdr().offsetToRva(codeBeginOffset + codeSize));
								return false;
							}

							// Set the address
							insn.address = imageBase + _peFile.getPEHdr().offsetToRva(codeBeginOffset + codeSize);

							codeSize += insn.decoded.length;
							codeData += insn.decoded.length;

							// Add to the routine stream.
							rtn.emplace_back(std::move(insn));
						}

						// We need to ensure that the size of the code to be mutated
						// is enough to allow a JMP encoding
						if (rtn.codeSize() >= 10)
						{
							// printf("** ORIGINAL CODE SIZE: 0x%x **\n", rtn.codeSize());

							// Wipe out the existing code
							_peFile.scrambleVaData(rtn.getAddress() - imageBase - 5, rtn.codeSize() + 10);

							// Assign the flag to the routine (whether to mutate, virtualize, etc..)
							rtn.addFlag(std::get<0>(markers));
							_routines.emplace_back(std::move(rtn));

							// Write original code size for later use
							_peFile.buffer().deref<u32>(
								_peFile.getPEHdr().rvaToOffset(_routines.back().getAddress() - getBaseAddress()) - 5) = _routines.back().codeSize();
						}
						else
						{
							logger()->critical("Routine 0x{:X} is too small to be mutated!", rtn.getAddress());
						}
					}
				}
			}
		}
	}


	return !_routines.empty();
}

#include <algorithm>
#include <math.h>


X86BA_TEMPLATE bool X86BinaryApplication<BitSize>::addRoutineByAddress(uptr address, int marker)
{
	// No duplicates
	for (auto& rtn : _routines)
	{
		if (rtn.getAddress() == address)
			return false;
	}

	u32 rva = address - getBaseAddress();
	u32 offset = _peFile.getPEHdr().rvaToOffset(rva);
	pe::SectionHeader* sec = &_peFile.getSectionHdrFromVa(rva);

	if (!sec || !(sec->getCharacteristics() & pe::SCN_MEM_EXECUTE))
	{
		logger()->critical("Invalid address (0x{:X}) passed into X86BinaryApplication::addRoutineAddress!", address);
		return false;
	}

	//printf("addRoutineByAddress: 0x%llx\n", address);


	// Here, instead of making a new structure called `BasicBlock`, we just use `Routine` 
	// to list them all, so a vector<Routine>. We don't really need to know a block's parent/etc,
	// since we just want to know which block ends at the highest address to get a rough calculation of the size.
	std::vector<Routine> blocks { };
	std::vector<size_t> codeOffsets { };
	uptr cur_highest = 0ull;
	uptr nextKnownAddress = 0ull;
	uptr knownEndOfFunc = 0ull;

	uint8_t* fileBuf = _peFile.base();

	blocks.push_back({});
	codeOffsets.push_back(0);

	//
	// Get the function subsequent to the target function if possible using mapped symbols.
	if (!_mapSymbols.empty())
	{
		for (auto& sym : _mapSymbols)
		{
			if (_mapType == MapFileType::kIDAPro)
			{
				// GHETTO - Ignore locations!
				if (sym.name.find("loc_") != std::string::npos ||
					sym.name.find("def_") != std::string::npos)
					continue;
			}

			u64 addr = sym.address;

			if (addr == 0ull && sym.sectionIndex != 0)
			{
				addr = sym.sectionOffset;
				addr += _peFile.getSectionHdr(sym.sectionIndex - 1).getVirtualAddress();
				addr += getBaseAddress();
			}

			if (addr > address)
			{
				nextKnownAddress = addr;
				break;
			}
		}
	}

	// How this works: 
	// - We use a vector of current code offsets and a vector of routines that symbolize our basic blocks.
	// -- The last element in the `codeOffsets` vector will correspond to the last element in basic block list (`blocks`).
	// - Once we hit a terminating instruction (jcc/ret..), we perform one of two actions
	// *- On a JCC terminating instruction, we calculate the dst of the JCC and create a new basic block and corresponding
	// -- offset. We keep going until a RET is hit.
	// *- When a RET is hit, we add a dummy block, then pop off an element in codeOffsets. If `codeOffsets` becomes empty, it means
	// -- we've visited all blocks.

	while (true)
	{
		// Once codeOffsets is empty, we've observed all blocks.
		if (codeOffsets.empty())
		{
			break;
		}

		instruction_t insn { };
		
		if (!Disassembler::instance()->decode(&fileBuf[offset + codeOffsets.back()], &insn))
		{
			logger()->error("Instruction decode failure: rva(0x{:X} + 0x{:X})", rva, codeOffsets.back());			
			break;
		}

		// Really ghetto check.. but some functions end in calls (fastfails, MSVC generated, etc),
		// this is an easy way to determine if an end of function is being 
		if (insn.decoded.opcode == 0x90 || insn.decoded.opcode == 0xCC)
		{
			int numInt3s = insn.decoded.opcode == 0x90 ? 1 : 0;
			while (fileBuf[offset + codeOffsets.back() + numInt3s + 1] == 0xCC)
				++numInt3s;

			if (numInt3s >= 2)
				break;
		}

		// Set the address
		insn.address = address + codeOffsets.back();

		//
		// Update the title, which we use for to print the cur. progress.
		auto s = fmt::format("PERSES: Observing.. [0x{:X}]", insn.address);
		SetConsoleTitleA(s.c_str());

		if (insn.address > cur_highest)
		{
			cur_highest = insn.address;
		}

		// Integrity check, make sure we're not crossing into the next function
		if (nextKnownAddress != 0ull)
		{
			if (insn.address >= nextKnownAddress)
			{
#ifdef PERSES_VERBOSE
				printf("[ERROR]: Entering boundaries of another function - breaking out.\n");
#endif
				break;
			}
		}

		blocks.back().push_back(insn);

		if (insn.isMnemonic(ZYDIS_MNEMONIC_MOV) && insn.decoded.operand_count_visible == 2)
		{
			// Handle jump tables on x64.
			if constexpr (BitSize == PERSES_64BIT)
			{
				if (insn.isOperandType(0, ZYDIS_OPERAND_TYPE_REGISTER) &&
					insn.isOperandType(1, ZYDIS_OPERAND_TYPE_MEMORY))
				{
					// Add the new block
					std::vector<JumpTableEntry> jtes;
					if (inquireJumpTable(&insn, blocks.front().getAddress(), 0, 0, jtes))
					{
						// Update current offset
						codeOffsets.back() += insn.decoded.length;

						for (auto& entry : jtes)
						{
							u64 abs = entry.address;
							u32 off = _peFile.getPEHdr().rvaToOffset((u32)abs) - offset;

							// Add the new block
							blocks.push_back({});
							codeOffsets.push_back(off);
						}

						continue;
					}
				}
			}
		}

		if (Disassembler::instance()->isBbTerminatorInstruction(&insn))
		{
			//printf("BB terminator: %s\n", 
			//	Disassembler::instance()->format(address + codeOffsets.back(), &insn.decoded, insn.operands).c_str());

			if (insn.isMnemonic(ZYDIS_MNEMONIC_RET))
			{
				// Add the new block
				blocks.push_back({});
				codeOffsets.pop_back();
				continue;
			}

			// Handle jump tables on x86.
			if constexpr (BitSize == PERSES_32BIT)
			{
				if (insn.isMnemonic(ZYDIS_MNEMONIC_JMP) &&
					insn.isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY))
				{
					// Add the new block
					std::vector<JumpTableEntry> jtes;
					if (inquireJumpTable(&insn, blocks.front().getAddress(), 0, 0, jtes))
					{
						// Assume end of function is just above the jump table.
						if (knownEndOfFunc == 0ull || (insn.operands[0].mem.disp.value < knownEndOfFunc))
							knownEndOfFunc = insn.operands[0].mem.disp.value;

						// Update current offset
						codeOffsets.back() += insn.decoded.length;

						for (auto& entry : jtes)
						{
							u64 abs = entry.address;
							abs -= getBaseAddress();
							u32 off = _peFile.getPEHdr().rvaToOffset((u32)abs) - offset;

							// Add the new block
							blocks.push_back({});
							codeOffsets.push_back(off);
						}

						continue;
					}
				}
			}
			
			if (!insn.decoded.operand_count_visible ||
				!insn.isOperandType(0, ZYDIS_OPERAND_TYPE_IMMEDIATE))
			{
				// Add the new block
				blocks.push_back({});
				codeOffsets.pop_back();
				continue;
			}

			u64 abs = Disassembler::instance()->calcAbsolute(&insn);

			// printf("Taking branch: 0x%llx\n", abs);

			if (abs < address || abs > insn.address)
			{
				if (abs < address)
				{
					blocks.push_back({});
					codeOffsets.pop_back();
					continue;
				}

				bool observed = false;

				if (!_mapSymbols.empty())
				{
					for (auto& sym : _mapSymbols)
					{
						if (_mapType == MapFileType::kIDAPro)
						{
							// GHETTO - Ignore locations!
							if (sym.name.find("loc_") != std::string::npos ||
								sym.name.find("def_") != std::string::npos)
								continue;
						}

						u64 addr = sym.address;

						if (addr == 0ull && sym.sectionIndex != 0)
						{
							addr = sym.sectionOffset;
							addr += _peFile.getSectionHdr(sym.sectionIndex - 1).getVirtualAddress();
							addr += getBaseAddress();
						}

						if (abs == addr)
						{
							// printf("Breaking out due to known symbol: %s\n", sym.name.c_str());

							blocks.push_back({});
							codeOffsets.pop_back();
							observed = true;
							break;
						}
					}
				}
				else
				{
					for (auto& rtn : _routines)
					{
						if (rtn.getAddress() == abs)
						{
							blocks.push_back({});
							codeOffsets.pop_back();
							observed = true;
							break;
						}
					}
				}


				// TODO: Figure out if the JMP goes into another function without symbols.

				//blocks.push_back({});
				//codeOffsets.pop_back();
				if (observed)
				{
				//	printf("OBSERVED! 0x%llx\n", insn.address);
					continue;
				}
			}


			// Avoid infinite loop by breaking out when a block has already been observed.
			if (!blocks.empty())
			{
				bool skip = false;

				for (auto& blk : blocks)
				{
					if (!blk.empty() && blk.front().address == abs)
					{
						skip = true;
						break;
					}
				}

				if (skip)
				{
					codeOffsets.back() += insn.decoded.length;
					continue;
				}
			}


			abs -= getBaseAddress();
			u32 off = _peFile.getPEHdr().rvaToOffset((u32)abs);

			off -= offset;

			// Update current offset
			codeOffsets.back() += insn.decoded.length;

			// Add the new block
			blocks.push_back({});
			codeOffsets.push_back(off);

			continue;
		}

	Skip:
		codeOffsets.back() += insn.decoded.length;
	}

	u64 end = 0ull;
	u64 size = 0ull;
	u64 lastInsnLen = 0ull;


#ifdef PERSES_VERBOSE
	//logger()->info("** Built a routine from address [0x{:X}] **", address);

	for (auto& block : blocks)
	{
		if (block.empty())
		{
			continue;
		}

		//block.printAssembly();
	}
#endif

	if (knownEndOfFunc)
	{
		end = knownEndOfFunc - 1;
	}
	else
	{
		for (auto& block : blocks)
		{
			if (block.empty())
			{
				continue;
			}

			auto& terminating = block.back();

			// printf("Terminating address: 0x%llx\n", terminating.address);

			if (terminating.address > end)
			{
				end = terminating.address;
				lastInsnLen = terminating.decoded.length;
			}
		}
	}
	
	// Make VA
	if (end == 0)
		return false;

#ifdef PERSES_VERBOSE
	logger()->debug("Identified routine: [0x{:x} - 0x{:x}] ({} bytes in size)", address, end, (end + lastInsnLen) - address);
#endif


	size = end - address;


	if ((end + lastInsnLen) - address < ((BitSize == PERSES_64BIT) ? 14 : 25))
	{
#ifdef PERSES_VERBOSE
		printf("- Routine too small.\n"); 
#endif
		return false;
	}

	// We *should* just pull the blocks in and build a routine from that but since
	// we only observe blocks to determine end address, and dont sync them to a parent block, 
	// we can't ensure the order of blocks.
	if (!knownEndOfFunc)
		size += lastInsnLen;

	Routine rtn{};
	u32 so = 0;
	while (so < size)
	{
		instruction_t insn{ };
		if (!Disassembler::instance()->decode(&fileBuf[offset + so], &insn))
		{
			logger()->error("Instruction decode failure 2: rva(0x{:X} + 0x{:X})", rva, codeOffsets.back());
			break;
		}

		// Set the address
		insn.address = address + so;

		rtn.push_back(insn);
		so += insn.decoded.length;
	}

	// Wipe out the existing code
	_peFile.scrambleVaData(rva, size);

	// Assign the flag to the routine (whether to mutate, virtualize, etc..)
	rtn.addFlag(marker);
	_routines.emplace_back(std::move(rtn));

	// Signal to the linker that we write a detour and don't jump back at all.
	
	_peFile.buffer().deref<u32>(_peFile.getPEHdr().rvaToOffset(rva)) = PERSES_MUTATE_FULL;
	
	return true;
}

template<int BitSize>
bool X86BinaryApplication<BitSize>::addRoutineBySymbol(std::string_view symbolName, int marker)
{
	if (_mapSymbols.empty())
		return false;

	for (auto& symbol : _mapSymbols)
	{
		if (symbol.sectionIndex == 0)
			continue;

		if (symbol.name == symbolName)
		{
			// Calculate address manually, we can't rely on `symbol.address` since 
			// it may be 0 (IDA Pro .map)
			
			uptr addr = symbol.sectionOffset;
			int secIdx = symbol.sectionIndex - 1;
			pe::SectionHeader* hdr = &_peFile.getSectionHdr(secIdx);

			// Routine's can only be in executable sections.
			if (!(hdr->getCharacteristics() & pe::SCN_MEM_EXECUTE))
				return false;

			// Make absolute
			addr += getBaseAddress();
			addr += hdr->getVirtualAddress();

			return addRoutineByAddress(addr, marker);
		}
	}

	return false;
}

template<int BitSize>
bool X86BinaryApplication<BitSize>::addRoutineBySymbol(const MapSymbol* symbol, int marker)
{
	if (symbol->sectionIndex == 0)
		return false;

	uptr addr = symbol->sectionOffset;
	int secIdx = symbol->sectionIndex - 1;
	pe::SectionHeader* hdr = &_peFile.getSectionHdr(secIdx);

	// Routine's can only be in executable sections.
	if (!(hdr->getCharacteristics() & pe::SCN_MEM_EXECUTE))
		return false;

	// Make absolute
	addr += getBaseAddress();
	addr += hdr->getVirtualAddress();

	return addRoutineByAddress(addr, marker);
}

template<int BitSize>
bool X86BinaryApplication<BitSize>::addRoutineByAddress(uptr start, uptr end, int marker)
{
	uptr rva = start - getBaseAddress();
	uptr offset = _peFile.getPEHdr().rvaToOffset(rva);
	uptr index = 0ull;
	uint8_t* fileBuf = _peFile.base();
	Routine rtn {};

	while (true)
	{
		instruction_t insn { };

		if (!Disassembler::instance()->decode(&fileBuf[offset + index], &insn))
		{
			// logger()->error("Instruction decode failure: rva [ 0x{:X} ]", rva + index);
			break;
		}

		insn.address = start + index;

		if (insn.address == end)
			break;

		u8 len = insn.decoded.length;

		rtn.emplace_back(std::move(insn));

		index += len;
	}

	if (rtn.empty())
		return false;

	if (index < ((BitSize == PERSES_64BIT) ? 14 : 25))
		return false;

	// Wipe out the existing code
	_peFile.scrambleVaData(rva, (end-start));

	// Assign the flag to the routine (whether to mutate, virtualize, etc..)
	rtn.addFlag(marker);
	_routines.emplace_back(std::move(rtn));

	// Signal to the linker that we write a detour and don't jump back at all.
	_peFile.buffer().deref<u32>(_peFile.getPEHdr().rvaToOffset(rva)) = PERSES_MUTATE_FULL;

	return true;
}

X86BA_TEMPLATE bool X86BinaryApplication<BitSize>::transformRoutines()
{
	if (_routines.empty())
		return false;

	size_t idx = 0ull;

	if (_routines.size() > 100)
	{
		logger()->info("Grab a coffee, this may take a while ({} routines)..", _routines.size());
	}
	else
	{
		logger()->info("Beginning transform on {} routines..", _routines.size());
	}

	// Guesstimate.. Fix this..
	_peFile.getRelocDir().extend(((_routines.size() + 0x3) & ~0x3) * 0x100);

	for (auto& rtn : _routines)
	{
		//
		// Update the title, which we use for to print the cur. progress.
		auto s = fmt::format("PERSES: Applying transforms on routine [{}/{}]", idx, _routines.size());
		SetConsoleTitleA(s.c_str());

		SharedProtectionSchema schema = buildSchema(rtn.getFlag());

		// Apply transforms on the routine
		schema->applyTransforms(&rtn);

		++idx;
	}

	return true;
}

X86BA_TEMPLATE bool X86BinaryApplication<BitSize>::isRelocationPresent(u32 rva)
{
	return std::ranges::find(_originalRelocs, rva) != _originalRelocs.end();
}

X86BA_TEMPLATE void X86BinaryApplication<BitSize>::removeRelocation(u32 rva)
{
	// Allow the PE ldr to ignore the reloc. at the specified rva (if it exists)
	_peFile.getRelocDir().changeRelocationType(rva, pepp::RelocationType::REL_BASED_ABSOLUTE);
}

X86BA_TEMPLATE void X86BinaryApplication<BitSize>::dumpRoutines()
{
	for (auto& rtn : _routines)
		rtn.printAssembly();
}

X86BA_TEMPLATE void X86BinaryApplication<BitSize>::linkCode(Routine* origRtn, assembler::CodeHolder& code, const std::vector<RelocationEntry>& relocs, const std::vector<JumpTableEntry>& jumpTable)
{
	if (code.codeSize() == 0)
		return;

	uptr sectionAddr = _persesAddr ? _persesAddr : (_persesAddr = getBaseAddress() + _peFile.getPEHdr().getNextSectionRva()); // hdr.getVirtualAddress();
	uptr curAddr = sectionAddr + _currentSectionOffset;

	// Relocate the new routine to the section address.
	code.relocateToBase(curAddr);

	assembler::Section* section = code.sectionById(0);
	assembler::CodeBuffer& buf = section->buffer();

	// Set the routine address to the space in the section
	if (!buf.empty())
	{
		pepp::mem::ByteVector bv;
		bv.resize(buf.size());
		memcpy(&bv[0], buf.data(), buf.size());

		// Advance the section stream offset.
		_currentSectionOffset += bv.size() + 0xA;

		// Bind the address so the compile method can re-route code to mutated routines.
		_proutines[origRtn->getAddress()] = std::make_pair(curAddr, std::move(bv));

		// Build new relocation block information
		int relocSize = std::count_if(relocs.begin(), relocs.end(), [](const RelocationEntry& re) { return re.length == 0; });
		
		u32 rva = (curAddr - getBaseAddress());

		// We *could* handle this in one loop, but to be consistent with compiler relocation outputs
		// and have some actual readable code, we do it this way. Actual PE relocation handling will happen
		// at compile time (x86BinaryApplication::compile).
		for (auto& re : relocs)
		{
			if (re.length)
			{
				// On x64, we need to apply the other "relocs" (rip-relative fixes)
				// after the code has been embedded
				_newRelocs.push_back(re);
				_newRelocs.back().stream = curAddr;

				continue;
			}

			if (re.offset == 0ul)
			{
				// TODO: Figure out why this happened
				continue;
			}

			// NOTE: We will only create relocation blocks with VA's that are
			// aligned to PAGE_SIZE, which is consistent with the output of a 
			// compiler (MSVC).

			u32 rvaAligned = rva & ~0xfff;
			u32 compRva = rva + re.offset;
			u32 compRvaAligned = compRva & ~0xfff;

			RelocationEntry newEntry = re;

			// Check if the relocation offset intersects with the next page block
			if (compRvaAligned != rvaAligned)
			{
				// Append to the next block if so
				newEntry.offset = (compRva - compRvaAligned);
				_relocBlocks[compRvaAligned].emplace_back(std::move(newEntry));
			}
			else
			{
				// Add the remaining amount to the offset since we can ensure 
				// that the RVA of the block is the same.
				newEntry.offset += (rva & 0xfff);
				_relocBlocks[rvaAligned].emplace_back(std::move(newEntry));
			}
		}


		// Fixup existing jump tables
		// - NOTE: On x64, the jump tables entries are RVAs to the block.
		if constexpr (BitSize == PERSES_64BIT)
			curAddr -= getBaseAddress();

		for (auto& jte : jumpTable)
		{
			// printf("** Fixing JTE at 0x%llx - new: 0x%llx\n", getBaseAddress() + jte.rva, jte.newOffset + curAddr);

			_peFile.buffer().deref<u32>(_peFile.getPEHdr().rvaToOffset(jte.rva)) =
				jte.newOffset + curAddr;
		}
	}

}

X86BA_TEMPLATE void X86BinaryApplication<BitSize>::compile()
{
	uptr imageBase = _peFile.getImageBase();

	logger()->debug("Compiling/placing {} mutated routines.", _proutines.size());
	
	
	//
	// Append all relocations
	for (auto it = _relocBlocks.begin(); it != _relocBlocks.end(); ++it)
	{
		u32 rva = it->first;
		std::vector<RelocationEntry> const &entries = it->second;

		if (entries.empty())
			continue;

		// Pad the amount of relocs to ensure 32bit alignment
		size_t relocEntrySize = (entries.size() + 0x3) & ~0x3;
		size_t numHandled = 0ull;

		// Create the BlockStream and add all relocatables.
		pe::BlockStream bs = _peFile.getRelocDir().createBlock(rva, relocEntrySize);

		if (!bs.valid())
			continue;

		// printf("relocEntrySize: 0x%llx entries\n", relocEntrySize);

		for (auto& entry : entries)
		{
			bs.append(entry.type, entry.offset);
			++numHandled;
		}

		// Pad.
		for (size_t handled = numHandled; handled < relocEntrySize; ++handled)
		{
			bs.append(pe::RelocationType::REL_BASED_ABSOLUTE, 0);
		}
	}

	pe::SectionHeader& reloc = _peFile.getSectionHdr(".reloc");
	std::uint32_t fileAlignment = _peFile.getPEHdr().getOptionalHdr().getFileAlignment();

	u32 sizeOfBlocksSum = _peFile.getRelocDir().getTotalBlockSize();

	// Thanks to JustMagic for helping me catch this slipup - the PE loader will NOT apply relocations
	// unless the reloc. section's size attributes fit the sum(all SizeOfBlock)
	if (sizeOfBlocksSum != reloc.getVirtualSize())
	{
		if (sizeOfBlocksSum < reloc.getVirtualSize())
		{
			u32 delta = reloc.getVirtualSize() - sizeOfBlocksSum;
			// We can't reduce the size of the reloc. section, because in
			// `linkCode` we've already established the PERSES section address.
			// We must work with what we've already set and expand.
			_peFile.getRelocDir().adjustBlockToFit(delta);
		}
		else
		{
			// __debugbreak();
		}
	}

	pe::SectionHeader& hdr = _peFile.getSectionHdr(".perses");

	_peFile.appendSection(".perses", _currentSectionOffset + 0x1000,
		pe::SectionCharacteristics::SCN_MEM_READ | pe::SectionCharacteristics::SCN_MEM_EXECUTE | pepp::SectionCharacteristics::SCN_CNT_CODE, &hdr);

	for (auto it = _proutines.begin(); it != _proutines.end(); ++it)
	{
		uptr origAddr = it->first;

		u32 rva = origAddr - getBaseAddress();
		uptr newAddress = it->second.first;
		pepp::mem::ByteVector& rtn = it->second.second;

		uptr origOffset = _peFile.getPEHdr().rvaToOffset(rva);
		uptr newOffset = _peFile.getPEHdr().rvaToOffset(newAddress - getBaseAddress());

		pepp::mem::ByteVector detourStub;
		size_t detourAddOffset = 0;
		size_t addInsnOffset = 0;
		size_t originalRoutineSize = 0;
		u32 rtnSize = rtn.size();

		// printf("** DEBUG: Original routine address: 0x%llx => 0x%llx **\n", origAddr, newAddress);

		originalRoutineSize = _peFile.buffer().deref<u32>(origOffset);

		// Travel backwards on markered routines.
		if (originalRoutineSize != PERSES_MUTATE_FULL)
		{
			origOffset -= PERSES_MARKER_SIZE;
			rva -= PERSES_MARKER_SIZE;
			originalRoutineSize = _peFile.buffer().deref<u32>(origOffset);
		}
		
		if constexpr (BitSize == PERSES_64BIT)
		{
			detourAddOffset = 9;
			addInsnOffset = 5;

			detourStub.push_args
			(
				0xE8, 0x00, 0x00, 0x00, 0x00,
				0x48, 0x81, 0x04, 0x24, 0xAD, 0xDE, 0x00, 0x00,
				0xC3
			);

			if (originalRoutineSize != PERSES_MUTATE_FULL)
				originalRoutineSize += PERSES_MARKER_SIZE /*+5 for the end marker*/;
		}
		
		if constexpr (BitSize == PERSES_32BIT)
		{
			if (originalRoutineSize == PERSES_MUTATE_FULL)
			{
				detourAddOffset = 8;
				addInsnOffset = 5;

				detourStub.push_args
				(
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x81, 0x04, 0x24, 0xEF, 0xBE, 0xAD, 0xDE,
					0xC3
				);
			}
			else
			{
				detourAddOffset = 20;
				addInsnOffset = 17;

				detourStub.push_args
				(
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x81, 0x04, 0x24, 0x0D, 0x0D, 0x0D, 0x0D,
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x81, 0x04, 0x24, 0xEF, 0xBE, 0xAD, 0xDE,
					0xC3
				);
				// Since the mutated routine doesn't use flags,
				// we just abuse the value to store the original routine size for our return address.
				detourStub.deref<u32>(8) = originalRoutineSize + PERSES_MARKER_SIZE /*+5 for the end marker*/;
			}
		}

		detourStub.deref<u32>(detourAddOffset) = (newAddress - getBaseAddress()) - (rva + addInsnOffset);

		if constexpr (BitSize == PERSES_64BIT)
		{
			size_t rtnOffset = rtn.size();
			u64 newRva = newAddress - getBaseAddress();

			if (originalRoutineSize != PERSES_MUTATE_FULL)
			{
				u64 dst = (rva + originalRoutineSize + PERSES_MARKER_SIZE);
				u64 cur = (newRva + rtnOffset + 5);

				rtn.push_byte(0xE9);
				rtn.push_dword((u32)(dst-cur));
			}
			else
			{
				rtn.push_back(0xc3);
			}
		}
		else
		{
			// Add the RET instruction
			rtn.push_back(0xc3);
		}

		if (newOffset < 0x400)
		{
			logger()->critical("newOffset in invalid boundaries : 0x{:X}\n", newOffset);
#ifdef PERSES_DEBUGGABLE
			__debugbreak();
#endif
		}

		// Write the mutated routine into the new section
		memcpy(&_peFile.base()[newOffset], rtn.data(), rtn.size());
		// Write the detour
		memcpy(&_peFile.base()[origOffset], detourStub.data(), detourStub.size());
	}

	// Fix up RIP-relative stuff
	if constexpr (BitSize == PERSES_64BIT)
	{
		logger()->info("[x64] Fixing {} RIP relative instructions.", _newRelocs.size());

		for (auto& re : _newRelocs)
		{
			// Dumb down to RVAs
			//printf("ptr: 0x%llx\n", re.absolute);
			//printf("base: 0x%x\n", re.base);
			//printf("offset: 0x%x\n", re.offset);

			u64 ptr = re.absolute - getBaseAddress();
			u64 newInsn = (re.stream - getBaseAddress()) + (re.base);

			//printf("WriteOffset: 0x%llx\n", newInsn + (re.offset - re.base));

			u32 writeOffset = _peFile.getPEHdr().rvaToOffset(newInsn + (re.offset - re.base));

			if (writeOffset != 0)
				// Fixup the relative.
				_peFile.buffer().deref<u32>(writeOffset) = (ptr - (newInsn + re.length));
		}
	}

	// Incase we somehow messed up, ensure all offsets in gs_retGadgets in MutationLight are actually RET.
	for (auto addr : getKnownRetGadgets())
	{
		addr -= getBaseAddress();
		u32 offset = _peFile.getPEHdr().rvaToOffset(addr);
		_peFile.base()[offset] = 0xc3;
	}

	_filePath.replace_extension(_peFile.isDll() ? ".perses.dll" : _peFile.isSystemFile() ? ".perses.sys" : ".perses.exe");

	logger()->info("Compiling to {}", _filePath.string());

	_peFile.writeToFile(_filePath.string());
}

X86BA_TEMPLATE bool X86BinaryApplication<BitSize>::linkMapFile(MapFileType type, std::filesystem::path filePath)
{
	MapFileParser* parser = nullptr;

	// TODO: Add LLVM support.
	switch (type)
	{
	case MapFileType::kIDAPro:
		parser = new IDAMapFileParser();
		break;
	case MapFileType::kMSVC:
		parser = new MSVCMapFileParser();
		break;
	default:
		return false;
	}

	if (parser != nullptr)
	{
		if (parser->parse(filePath))
		{
			_mapType = type;
			_mapSymbols = std::move(parser->getSymbols());
		}

		delete parser;
		return true;
	}

	return false;
}

template<int BitSize>
bool perses::X86BinaryApplication<BitSize>::hasMapFile() const
{
	return !_mapSymbols.empty();
}

template<int BitSize>
bool X86BinaryApplication<BitSize>::inquireJumpTable(instruction_t* insn, uptr begin, uptr end, int entryCount, std::vector<JumpTableEntry>& entries)
{
	// NOTE: This was only tested on MSVC (VS2022), so this may have to be tweaked
	// to support the output of different compilers.
	int entryIdx = 0;

	if constexpr (BitSize == PERSES_32BIT)
	{
		if (!insn->isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY) || !insn->operands[0].mem.disp.has_displacement)
			return false;

		u64 dst = insn->operands[0].mem.disp.value;
		u32 rva = dst - getBaseAddress();
		u32 offset = getImage().getPEHdr().rvaToOffset(rva);
		u32 scale = std::max<u32>((u32)insn->operands[1].mem.scale, sizeof(u32));
		
		// Try to force `end` value if we were supplied null.
		if (!end)
		{
			end = dst;
			
			if (end < begin)
				end = begin + 0x100;
		}


		u32 jmpTableEntry = getImage().buffer().deref<u32>(offset);

		while (jmpTableEntry >= getBaseAddress() &&
			   jmpTableEntry <= getBaseAddress() + getImage().buffer().size())
		{
			if (entryCount != 0)
			{
				if (entryIdx >= entryCount)
					break;

				++entryIdx;
			}

			if (jmpTableEntry >= begin && jmpTableEntry <= end)
				entries.emplace_back(rva, jmpTableEntry, 0ul);

			offset += scale;
			rva += scale;

			jmpTableEntry = getImage().buffer().deref<u32>(offset);
		}

		return !entries.empty();
	}
	else
	{
		// * Below is a disassembly listing of a jump table compiled with MSVC x64 (VS2022)
		// *
		// - lea     rax, cs:140000000h
		// - mov     ecx, ds:(jpt_1400010ED - 140000000h)[rax+rcx*4]
		// - add     rcx, rax
		// - jmp     rcx  ; switch jump
		// *

		ZydisRegister base = insn->operands[1].mem.base;
		ZydisRegister index = insn->operands[1].mem.index;
		u32 scale = (u32)insn->operands[1].mem.scale;

		// This is an RVA already
		u64 dispRva = insn->operands[1].mem.disp.value;
		u32 dispOffset = getImage().getPEHdr().rvaToOffset(dispRva);

		// Try to force `end` value if we were supplied null.
		if (!end)
		{
			end = getBaseAddress() + dispRva;

			if (end < begin)
				end = begin + 0x100;
		}

		// Not a relative JMP.
		if (base == ZYDIS_REGISTER_RIP || dispOffset == 0ul)
			return false;

		u32 entry = getImage().buffer().deref<u32>(dispOffset);

		while (entry >= (begin - getBaseAddress()) && entry <= (end - getBaseAddress()))
		{
			if (entryCount != 0)
			{
				if (entryIdx >= entryCount)
					break;

				++entryIdx;
			}

			entries.emplace_back(dispRva, entry, 0ul);

			dispRva += scale;
			dispOffset += scale;

			entry = getImage().buffer().deref<u32>(dispOffset);
		}

		return !entries.empty();
	}

	return false;
}

template<int BitSize>
bool X86BinaryApplication<BitSize>::parseFunctionList(std::filesystem::path path)
{
	if (!std::filesystem::exists(path))
		return false;

	std::ifstream infile(path);
	std::string line;

	int count = 0;

	while (std::getline(infile, line))
	{
		size_t idx = line.find(':');
		std::string startStr = line.substr(0, idx);
		std::string endStr = line.substr(idx + 1);
		uptr start = strtoull(startStr.c_str(), nullptr, 16);
		uptr end = strtoull(endStr.c_str(), nullptr, 16);
		
		if (addRoutineByAddress(start, end, PERSES_MARKER_MUTATION))
			++count;
	}

	return !_routines.empty();
}

X86BA_TEMPLATE assembler::Environment X86BinaryApplication<BitSize>::getEnvironment()
{
	static auto env32 { assembler::Environment(assembler::Arch::kX86) };
	static auto env64 { assembler::Environment(assembler::Arch::kX64) };

	if constexpr (BitSize == PERSES_64BIT)
		return env64;

	return env32;
}


#undef X86BA_TEMPLATE