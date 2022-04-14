#include "perses.hpp"

using namespace perses;
using namespace perses::assembler;

// Explicit templates.
template class MutationLightSchema<PERSES_32BIT>;
template class MutationLightSchema<PERSES_64BIT>;

#define MUT_TEMPLATE template<int BitSize>

static std::vector<u64> gs_retGadgets;

/*
NOTES:
 * -- TODO: Conditionals are not handled "properly" here, but in order to do so, the `Routine` class would need to be modified to handle basic blocks rather than entire blocks of code.
   ** Each routine should be analyzed in steps where the last instruction is a terminator instruction (e.g ret, jmp/jcc, etc) 
   ** Then each block can be separated and have passes run on them individually, the terminator instructions can be fixed to the new dst or mutated entirely.
 * -- This is still a very basic mutation/obfuscation schema. The major component is the immediate/memory encryption, where all original immediates or offsets
   ** are encrypted at compile time then decrypted during actual runtime of the code.
 * -- All calls/jmps and even jmps to jump tables are obfuscated, which will completely break decompiling analyzers from working properly.
   ** Further obfuscation can include JCC obfuscation, more MBA, or additional instructions.
*/

class CompilerErrorHandler : public ErrorHandler {
public:
	void handleError(Error err, const char* message, BaseEmitter* origin) override {
		logger()->critical("AsmJit compilation error: {} ({})\n", message, err);
#ifdef PERSES_DEBUGGABLE
		__debugbreak();
#endif
	}
};

MUT_TEMPLATE perses::assembler::CodeBuffer MutationLightSchema<BitSize>::applyTransforms(Routine* rtn)
{
	logger()->info("Applying transforms on routine 0x{:X}", rtn->getAddress());

	if (rtn->empty() || rtn->getFlag() != PERSES_MARKER_MUTATION)
		return {};

	_rtn = rtn;

	// Setup begin-end values
	_rtnBegin = rtn->getAddress();
	_rtnEnd = _rtnBegin + rtn->codeSize();

	// Initialize the CodeHolder
	this->_code.init(app()->getEnvironment());

	if (static std::atomic_bool x = true; x.exchange(false)) // Credits to Xerox for this one liner :)
	{
		// Don't include stuff that will change on runtime.
		auto it = std::remove_if(gs_retGadgets.begin(), gs_retGadgets.end(),	
			[this](u64& gadget)
			{
				u32 rva = toRva(gadget);

				for (auto reloc : app()->getOriginalRelocs())
				{
					if (rva >= reloc && rva <= (reloc + sizeof(u32)))
					{
						return true;
					}
				}

				for (auto& rtn : app()->getRoutines())
				{
					if (gadget >= rtn.getAddress() && gadget <= (rtn.getAddress() + rtn.codeSize()))
					{
						return true;
					}
				}
				return false;
			});
		
		gs_retGadgets.erase(it, gs_retGadgets.end());
	}

	// Add an error handler
	CompilerErrorHandler errHandler;
	this->_code.setErrorHandler(&errHandler);

	assembler::x86::Assembler* cc = this->getCompiler();

	// Attach the codeholder
	this->_code.attach(cc);

	// Variables needed for the entire compilation
	uptr start = rtn->getAddress();

	_streamOffset = 0ul;

	// See notes above regarding JCC handling. This is improper and can be
	// done properly by disassembling a function into basic blocks rather
	// than an entire blob of code. 
	// Alternatively, JCC instructions such as jnz, jz can be converted into conditional movs such as cmovnz, cmovz, etc..
	std::vector<std::pair<uint32_t, std::pair<asmjit::Label, bool>>> jccOffsets;
	std::map<uint32_t, asmjit::Label> positions;

	// Now build mutations on the X86 instruction level
	for (auto& insn : *rtn)
	{
		bool handled = false;

		// Update the current instruction
		_currentInstruction = &insn;

#ifdef PERSES_VERBOSE
	//	printf("> * Transforming 0x%llx (0x%x) - [ %s ]\n", 
	//		insn.address, _streamOffset,
	//		Disassembler::instance()->format(insn.address, &insn.decoded, insn.operands).c_str());
#endif

		// JCC fixups.
		for (auto& [offset, label] : jccOffsets)
		{
			if (offset == _streamOffset && !label.second)
			{
				// Bind the label
				Label& asmLabel = label.first;
				cc->bind(asmLabel);

				// Signify the label has been binded now
				label.second = true;
			}
		}

		// Bind each offset to a label (NOT GOOD)
		positions[_streamOffset] = cc->newLabel();
		cc->bind(positions[_streamOffset]);

		// Just like JCCs, we need to constantly check whether we are hitting a jump table entry
		for (auto& jte : _jumpTables)
		{
			uptr addr = insn.address;

			if constexpr (BitSize == PERSES_64BIT)
			{
				// Jump table entries on x64 are RVAs.
				addr -= app()->getBaseAddress();
			}

			if (jte.address == addr)
			{
				// If we hit the jump table offset, bind (if not already) the label
				if (jte.label.id() == Globals::kInvalidId)
				{
					jte.label = cc->newLabel();
					cc->bind(jte.label);
				}
			}
		}

		/**/
		switch (insn.decoded.mnemonic)
		{
		case ZYDIS_MNEMONIC_PUSH:
			handled = handlePush(&insn);
			break;
		case ZYDIS_MNEMONIC_MOV:
			handled = handleMov(&insn);
			break;
		case ZYDIS_MNEMONIC_CALL:
		case ZYDIS_MNEMONIC_JMP:
			handled = handleRelInstruction(&insn);

			if (handled)
				break;

			if constexpr (BitSize == PERSES_32BIT)
			{
				if (insn.isMnemonic(ZYDIS_MNEMONIC_JMP))
					handled = recoverJumpTable(&insn);
			}

			break;
		case ZYDIS_MNEMONIC_ADD:
			handled = handleAdd(&insn);
			break;
		case ZYDIS_MNEMONIC_XOR:
			handled = handleXor(&insn);
			break;
		default:
			handled = false;
			break;
		}

		if (!handled && 
			Disassembler::instance()->isJmp(&insn) && 
			insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			uptr va = insn.address;
			uptr dst = Disassembler::instance()->calcAbsolute(&insn);

			if (dst < _rtnBegin && dst > _rtnEnd)
			{
				goto Unhandled;
			}

			// JCCs that jump backward are handled differently
			if (dst < va)
			{
				// Try to find the label by assigned _streamOffset
				auto it = positions.find((dst - rtn->getAddress()));
				if (it != positions.end())
				{
					writeJcc(&insn.decoded, it->second);
				}

				goto UpdateStream;
			}

			//
			// Create a new label, when we reach the destination, we call
			// `asm->bind(*label)` -- This way we don't have to manually 
			// solve for the JCC relative deltas or the JCC type.
			Label lbl = cc->newLabel();
			dst -= rtn->getAddress();

			jccOffsets.emplace_back(dst, std::make_pair(lbl, false));

			// Write the JCC instruction now, so the label can be binded later
			writeJcc(&insn.decoded, lbl);
		}
		else if (!handled)
		{
		Unhandled:
			// Attempt to fixup relocations automatically.
			if (app() != nullptr && insn.decoded.operand_count_visible != 0)
			{
				ZydisInstructionSegments segs;
				ZydisGetInstructionSegments(&insn.decoded, &segs);

				// On x64, mostly everything is RIP relative, so we need to attempt to fix these automatically..
				if constexpr (BitSize == PERSES_64BIT)
				{
					for (u8 idx = 0; idx < insn.decoded.operand_count_visible; ++idx)
					{
						auto& op = insn.operands[idx];

						if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						{
							if (op.imm.is_relative)
							{
								for (u8 segIdx = 0; segIdx < segs.count; ++segIdx)
								{
									auto seg = segs.segments[segIdx];
									
									if (seg.type == ZYDIS_INSTR_SEGMENT_IMMEDIATE)
									{
										u64 absolute = Disassembler::instance()->calcAbsolute(&insn.decoded, &op, insn.address);
										makeRelocation(seg.offset, true, absolute);
										break;
									}
								}
							}
						}

						if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
						{
							if (op.mem.base == ZYDIS_REGISTER_RIP)
							{
								for (u8 segIdx = 0; segIdx < segs.count; ++segIdx)
								{
									auto seg = segs.segments[segIdx];

									if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
									{
										u64 absolute = Disassembler::instance()->calcAbsolute(&insn.decoded, &op, insn.address);
										makeRelocation(seg.offset, true, absolute);
										break;
									}
								}
							}
						}
					}
				}

				// Generic, will work on both x86 and x64.
				for (int i = 0; i < segs.count; ++i)
				{
					auto seg = segs.segments[i];

					if (seg.type != ZYDIS_INSTR_SEGMENT_DISPLACEMENT &&
						seg.type != ZYDIS_INSTR_SEGMENT_IMMEDIATE)
						continue;

					u32 idx = seg.offset;
					if ((idx + sizeof(u32) <= insn.raw.size()) &&
						*(u32*)&insn.raw[idx] >= app()->getBaseAddress())
					{
						// These checks are slow, which is why the above code is necessary.
						// Binaries can have hundreds of thousands of relocations.
						if (app()->isRelocationPresent(toRva(insn.address) + idx))
						{
							app()->removeRelocation(toRva(insn.address) + idx);
							// Now generate the relocation ourself for the current
							// instruction stream
							makeRelocation(idx);
						}
					}

				}
			}


			// Just embed the original code
			Error err = cc->embed(insn.raw.data(), insn.raw.size());
			if (err)
				logger()->critical("Error during embed: {}", err);
		}
		else
		{
#ifdef PERSES_VERBOSE
		//	printf("> * Transforming 0x%llx (0x%x) - [ %s ]\n",
		//		insn.address, _streamOffset,
		//		Disassembler::instance()->format(insn.address, &insn.decoded, insn.operands).c_str());
#endif
		}

	UpdateStream:
		_streamOffset += insn.decoded.length;
	}

	// Finish up the rest of the JCC offsets incase we have branches at the end.
	for (auto& [offset, label] : jccOffsets)
	{
		if (offset == _streamOffset && !label.second)
		{
			Label& asmLabel = label.first;
			cc->bind(asmLabel);
		}
	}

	cc->finalize();

	// Resolve all label offsets
	for (auto& jte : _jumpTables)
	{
		// Ensure its a binded label
		if (jte.label.id() != Globals::kInvalidId)
		{
			jte.newOffset = this->_code.labelOffset(jte.label);
		}
	}

	size_t relocImmIdx { 0ull };

	// Build a relocation table to pass to the linker.
	for (auto& le : this->_code.labelEntries())
	{
		if (!le || !le->hasName())
			continue;

		if (le->id() == Globals::kInvalidId)
		{
			PERSES_THROW("Relocation label was added but never binded!");
		}

		RelocGenEntry& relocInfo = _relocEntryList[relocImmIdx++];

		u32 relocOffset = (u32)le->offset() + relocInfo.roffset;
		this->_relocs.emplace_back(
			BitSize == PERSES_64BIT ? pepp::REL_BASED_DIR64 : pepp::REL_BASED_HIGHLOW, 
			relocOffset,
			le->offset(),
			relocInfo.length,
			relocInfo.absolute);
	}

	// Link the code, build PE sections, fix jump tables, relocs., RIP relative instructions ..
	if (app())
	{
		app()->linkCode(rtn, this->_code, this->_relocs, this->_jumpTables);
	}

	Section* section = this->_code.sectionById(0);
	CodeBuffer& buf = section->buffer();

	// Uncomment to get raw binary files of the mutated code.
#ifdef PERSES_DEBUGGABLE
	//pepp::io::File outbin("bin/compiler_out.bin", pepp::io::kFileOutput | pepp::io::kFileBinary);
	//outbin.Write(buf.data(), buf.size());
#endif 

	return buf;
}

MUT_TEMPLATE bool MutationLightSchema<BitSize>::handlePush(instruction_t* insn)
{
	// This obfuscation is only present on x86 (32bit), not x64.

	assembler::x86::Assembler* cc = this->getCompiler();

	if (app() && app()->getEnvironment().is64Bit())
		return false;

	if (insn->getOperand(0)->size != 32)
		return false;

	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY))
	{
		// e.g push offset (opcode: FF 35)
		if (insn->operands[0].mem.disp.has_displacement)
		{
			if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
				return false;

			if (insn->operands[0].mem.segment != ZYDIS_REGISTER_DS)
				return false;

			bool isRelocatable = app()->isRelocationPresent((insn->address - app()->getBaseAddress()) + 2);

			if (isRelocatable)
			{
				// We need to remove/ignore the relocation so that our code doesn't break when the PE ldr. attempts to
				// process the reloc. directory.
				app()->removeRelocation((insn->address - app()->getBaseAddress()) + 2);
			}

			u32 value = toRva((u32)insn->operands[0].mem.disp.value);
			u32 key = util::genRandInteger<u32>();

			value ^= key;
			value = _byteswap_ulong(value);

			cc->sub(x86::regs::esp, sizeof(u32));

			// Preserve EAX
			cc->push(x86::regs::eax);

			cc->mov(x86::regs::eax, value);
			cc->bswap(x86::regs::eax);
			cc->xor_(x86::regs::eax, key);
			// Load into previous stack alloc.
			cc->xchg(x86::dword_ptr(x86::regs::esp, 4), x86::regs::eax);

			if (app()->getImage().isDllOrSystemFile())
			{
				makeRelocation(0x1);
				cc->mov(x86::regs::eax, app()->getBaseAddress());
			}
			else
			{
				fetchPeb(x86::regs::eax);
				cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax, 8));
			}

			// Translate rva to va.
			cc->add(x86::dword_ptr(x86::regs::esp, 4), x86::regs::eax);
			cc->xchg(x86::dword_ptr(x86::regs::esp, 4), x86::regs::eax);
			cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax));
			cc->xchg(x86::dword_ptr(x86::regs::esp, 4), x86::regs::eax);

			cc->pop(x86::regs::eax);

			return true;
		}
		
		return false;
	}

	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_IMMEDIATE))
	{
		// Only handle opcode 0x68
		if (insn->decoded.opcode != 0x68)
			return false;

		if (insn->operands[0].imm.value.u == 0)
			return false;

		bool isRelocatable = app()->isRelocationPresent((insn->address - app()->getBaseAddress()) + 1);

		// Simple constant encryption, but enough to make decompilers generate some funky output.
		if (isRelocatable)
		{
			// We need to remove/ignore the relocation so that our code doesn't break when the PE ldr. attempts to
			// process the reloc. directory.
			app()->removeRelocation((insn->address - app()->getBaseAddress()) + 1);

			u32 rva = toRva(insn->operands[0].imm.value.u);
			u32 key = util::genRandInteger<u32>();
			u32 rots = util::genRandInteger<u32>(2, 14);
			u32 crypt = _rotl(rva ^ key, rots);

			cc->push(crypt);
			cc->pushfd();
			cc->ror(x86::dword_ptr(x86::regs::esp, 4), rots);
			cc->xor_(x86::dword_ptr(x86::regs::esp, 4), key);

			cc->push(x86::regs::eax);

			if (app()->getImage().isDllOrSystemFile())
			{
				// Add a relocation at this offset
				// TODO: Figure out how to do this properly with asmjit!?
				// For now, we just generate a dummy label, then we add 1 to the offset. mov eax, imm encoding is {A1 ..bytes..}
				makeRelocation(0x1);
				cc->mov(x86::regs::eax, app()->getBaseAddress());
			}
			else
			{
				// We can use the PEB to determine the active image base
				fetchPeb(x86::regs::eax);
				cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax, 8));
			}

			cc->add(x86::dword_ptr(x86::regs::esp, 8), x86::regs::eax);

			cc->pop(x86::regs::eax);
			cc->popfd();
		}
		else
		{
			u32 key = util::genRandInteger<u32>();
			u32 rots = util::genRandInteger<u32>(2, 14);
			u32 crypt = _rotl(insn->operands[0].imm.value.u ^ key, rots);

			cc->push(crypt);
			cc->push(x86::regs::eax);
			cc->pushfd();
			cc->xchg(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 8));
			cc->ror(x86::regs::eax, rots);
			cc->xor_(x86::regs::eax, key);
			cc->xchg(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 8));
			cc->popfd();
			cc->pop(x86::regs::eax);
		}

		return true;
	}


	return false;
}

MUT_TEMPLATE bool perses::MutationLightSchema<BitSize>::handleMov(instruction_t* insn)
{
	/*
	ZydisInstructionSegments segs;
	ZydisGetInstructionSegments(&insn->decoded, &segs);

	for (int i = 0; i < segs.count; ++i)
	{
		auto seg = segs.segments[i];
		
		printf("* Segment\n");
		printf("\t* Type: %d\n", seg.type);
		printf("\t* Size: %d\n", seg.size);
		printf("\t* Offset: 0x%x\n", seg.offset);
	}
	*/

	// NOTE: MOV does not affect RFLAGs, so preserve it
	// 

	if (insn->decoded.operand_count_visible < 2)
		return false;

	assembler::x86::Assembler* cc = this->getCompiler();
	assembler::x86::Gp stackReg;

	constexpr bool isx64 = BitSize == PERSES_64BIT;
	bool isDll = false;

	if (app())
	{
		isDll = app()->getImage().isDllOrSystemFile();
	}

	if constexpr (isx64)
		stackReg = x86::regs::rsp;
	else
		stackReg = x86::regs::esp;
	
	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_REGISTER))
	{
		bool isImm = insn->isOperandType(1, ZYDIS_OPERAND_TYPE_IMMEDIATE);
		bool isMem = insn->isOperandType(1, ZYDIS_OPERAND_TYPE_MEMORY);

		auto dst = x86util::getAsmRegAny(insn->operands[0].reg.value);

		if (isImm)
		{
			size_t offset = insn->getFirstSegmentOffset(ZYDIS_INSTR_SEGMENT_IMMEDIATE);
			bool isReloc = false;

			// Remove any relocation if needed
			if (app() && app()->isRelocationPresent(toRva(insn->address) + offset))
			{
				app()->removeRelocation(toRva(insn->address) + offset);
				isReloc = true;
			}

			if (isReloc)
			{
				if constexpr (isx64) // -- unlikely case.
				{
					u32 rva = toRva(insn->operands[1].imm.value.u);
					u32 key = util::genRandInteger<u32>();
					u32 rots = util::genRandInteger<u32>(1, 31);

					x86::Reg dstReg(dst);
					x86::Gpd dstDw = dst.r32();

					rva ^= key;
					rva = _rotl(rva, rots);
					rva = ~rva;
					rva = _byteswap_ulong(rva);

					cc->mov(dstDw, rva);
					cc->bswap(dstDw);
					cc->not_(dstDw);
					cc->ror(dstDw, rots);
					cc->xor_(dstDw, key);
					cc->push(dst);
					
					if (app()->getImage().isDllOrSystemFile())
					{
						cc->push(x86::regs::rax);
						makeRelocation(0x2);
						cc->mov(x86::regs::rax, app()->getBaseAddress());
						cc->add(x86::qword_ptr(stackReg, 8), x86::regs::rax);
						cc->pop(x86::regs::rax);
					}
					else
					{
						cc->push(x86::regs::rax);
						fetchPeb(x86::regs::rax);
						cc->mov(x86::regs::rax, x86::qword_ptr(x86::regs::rax, 0x10));
						cc->add(x86::qword_ptr(stackReg, 8), x86::regs::rax);
						cc->pop(x86::regs::rax);
					}

					cc->pop(dst);
					return true;
				}
				else
				{
					u32 rva = toRva((u32)insn->operands[1].imm.value.u);
					u32 key = util::genRandInteger<u32>();
					u32 rots = util::genRandInteger<u32>(1, 20);
					
					rva = ~rva;
					rva ^= key;

					if (rots >= 10)
						rva = _rotl(rva, rots);
					else
						rva = _rotr(rva, rots);

					cc->pushfd();
					// Generate a relocation for the base address
					makeRelocation(0x1);
					cc->push(app()->getBaseAddress());
					cc->push(rva);

					if (rots >= 10)
						cc->ror(x86::dword_ptr(stackReg), rots);
					else
						cc->rol(x86::dword_ptr(stackReg), rots);

					cc->xor_(x86::dword_ptr(stackReg), key);
					cc->not_(x86::dword_ptr(stackReg));

					// Load into dst reg.
					cc->pop(dst);
					// Translate rva to va
					cc->add(dst, x86::dword_ptr(stackReg));
					// Clean up
					cc->add(stackReg, sizeof(u32));

					cc->popfd();

					return true;
				}
			}
			else
			{
				cc->pushfd();
				// Generate a different algorithm dependent on size
				// growing in complexity respectively to size
				switch (insn->operands[1].size)
				{
				case PERSES_BYTESTOBITS(sizeof(u8)):
				{
					u8 imm = (u8)insn->operands[1].imm.value.u;
					imm = _rotl8(imm, 3);

					cc->mov(dst, imm);
					cc->ror(dst, 3);
					break;
				}
				case PERSES_BYTESTOBITS(sizeof(u16)):
				{
					u16 imm = (u16)insn->operands[1].imm.value.u;
					u16 key = util::genRandInteger<u16>();
					
					imm = ~imm;
					imm ^= key;

					cc->mov(dst, imm);
					cc->xor_(dst, key);
					cc->not_(dst);
					break;
				}
				// 32bit+ immediates will get 2 stage loads,
				// where the upper and lower portion are decrypted
				// separately then concatenated 
				case PERSES_BYTESTOBITS(sizeof(u32)):
				{
					// Temporary registers for use.
					const static x86::Gpd _r32ss[] =
					{
						x86::regs::ebx,
						x86::regs::ecx,
						x86::regs::edx
					};

					x86::Gp tmpGp = x86::regs::eax;
					x86::Reg tmpGpReg(tmpGp);

					if (dst == x86::regs::eax ||
						dst == x86::regs::rax)
					{
						tmpGp = _r32ss[rand() % ASMJIT_ARRAY_SIZE(_r32ss)];
						tmpGpReg = tmpGp;
					}

					x86::Gpw tmpGpW = x86::gpw(tmpGpReg.id());
					x86::GpbHi tmpGpHi = x86::gpb_hi(tmpGpReg.id());
					x86::GpbLo tmpGpLo = x86::gpb_lo(tmpGpReg.id());

					u16 upper = ((u32)insn->operands[1].imm.value.u) >> 16;
					u16 lower = ((u32)insn->operands[1].imm.value.u) & 0xffff;

					//printf("*** LOWER: 0x%x **\n", lower);
					//printf("*** UPPER: 0x%x **\n", upper);

					u16 keyUp = util::genRandInteger<u16>();
					u16 keyLow = util::genRandInteger<u16>();
					
					if (upper != 0)
					{
						upper = ~upper;
						upper ^= keyUp;
						upper = _byteswap_ushort(upper);
					}

					lower = _byteswap_ushort(lower);
					lower = ~lower;
					lower ^= keyLow;

					// Load lower portion
					cc->sub(stackReg, sizeof(u16));
					cc->mov(x86::word_ptr(stackReg), lower);


					// Load and decrypt the upper 16 bits
					x86::Reg dstReg(dst);
					x86::Gpw dstW = x86::gpw(dstReg.id());
					x86::Gpd dstDw = x86::gpd(dstReg.id());

					cc->mov(dstDw, upper);

					if (upper != 0)
					{
						// EDI/ESI/EBP aren't registers with 16bit subsections that can be used 
						// to swap the bytes. I use the easy way out and transfer control to
						// a temp register where the subsections needed are present.
						bool unsupported = false;

						x86::GpbHi dstHi = x86::gpb_hi(dstReg.id());
						x86::GpbLo dstLo = x86::gpb_lo(dstReg.id());
						
						// TODO: Do something better
						if (dstReg == x86::regs::edi ||
							dstReg == x86::regs::esi ||
							dstReg == x86::regs::ebp ||
							isx64 /*temporary*/)
						{
							unsupported = true;

							cc->push(tmpGp);
							cc->mov(tmpGp, dstDw);

							dstHi = tmpGpHi;
							dstLo = tmpGpLo;
						}

						cc->xchg(dstHi, dstLo);
						if (unsupported)
							cc->xchg(tmpGp, dstDw);
						cc->xor_(dstW, keyUp);
						cc->not_(dstW);
						cc->shl(dstDw, 16);

						if (unsupported)
						{
							cc->pop(tmpGp);
						}
					}


					// Decrypt the lower portion
					constexpr size_t stackOffset = isx64 ? sizeof(u64) : sizeof(u32);

					cc->push(tmpGp);
					cc->xor_(tmpGp, tmpGp);
					cc->mov(tmpGpW, x86::word_ptr(stackReg, stackOffset));
					cc->xor_(tmpGpW, keyLow);
					cc->not_(tmpGpW);
					cc->xchg(tmpGpLo, tmpGpHi);
					cc->xchg(tmpGpW, x86::word_ptr(stackReg, stackOffset));
					cc->pop(tmpGp);

					// OR the two values
					cc->mov(dstW, x86::word_ptr(stackReg));

					// Clean up
					cc->add(stackReg, sizeof(u16));

					// Copy the lower 32bits to the upper 32
					if (dst.size() == sizeof(u64))
					{
						cc->push(dst);
						cc->shl(x86::qword_ptr(stackReg), 32);
						cc->or_(x86::qword_ptr(stackReg), dst);
						cc->pop(dst);
					}

					break;
				}
				case PERSES_BYTESTOBITS(sizeof(u64)):
				{
					u32 upper = ((u64)insn->operands[1].imm.value.u) >> 32;
					u32 lower = ((u64)insn->operands[1].imm.value.u) & 0xffffffff;

					// Get reg. info
					x86::Reg dstReg(dst);
					x86::Gpd dstDw = x86::gpd(dstReg.id());

					u32 keyUp = util::genRandInteger<u32>();
					u32 keyLow = util::genRandInteger<u32>();

					lower ^= keyLow;
					lower = ~lower;
					lower = _byteswap_ulong(lower);
					lower = _rotl(lower, keyUp & 31);

					if (upper != 0)
					{
						upper ^= keyUp;
						upper = _rotr(upper, keyLow & 31);
						upper = _byteswap_ulong(upper);
						upper = ~upper;
					}

					cc->xor_(dst, dst);

					// Load and decrypt lower portion, and abuse xchg to generate aids pseudocode.
					cc->sub(stackReg, sizeof(u32));
					cc->mov(x86::dword_ptr(stackReg), dstDw);
					cc->sub(stackReg, sizeof(u32));
					cc->mov(x86::dword_ptr(stackReg), lower);
					cc->ror(x86::dword_ptr(stackReg), keyUp & 31);
					cc->xchg(x86::dword_ptr(stackReg), dstDw);
					cc->bswap(dstDw);
					cc->not_(dstDw);
					cc->xor_(dstDw, keyLow);
					cc->xchg(x86::dword_ptr(stackReg), dstDw);

					// Decrypt upper
					if (upper != 0)
					{
						cc->mov(dst, upper);
						cc->not_(dstDw);
						cc->bswap(dstDw);
						cc->rol(dstDw, keyLow & 31);
						cc->xor_(dstDw, keyUp);
						cc->shl(dst, 32);
						cc->or_(dst, x86::qword_ptr(stackReg));
					}
					else
					{
						cc->mov(dstDw, x86::dword_ptr(stackReg));
					}

					// Clean up
					cc->add(stackReg, sizeof(u32));
					cc->add(stackReg, sizeof(u32));

					break;
				}

				}


				cc->popfd();
				return true;
			}
		}

		if (isMem)
		{
			// Handle jump tables.
			if constexpr (isx64)
			{
				if (recoverJumpTable(insn))
					return true;
			}

			if (insn->operands[1].mem.segment != ZYDIS_REGISTER_DS)
			{
				return false;
			}

			if (insn->operands[1].mem.disp.has_displacement)
			{
				if constexpr (isx64)
				{
					if (insn->operands[1].mem.base != ZYDIS_REGISTER_RIP)
						return false;
					if (insn->operands[1].mem.index != ZYDIS_REGISTER_NONE)
						return false;
				}
				else
				{
					if (insn->operands[1].mem.base != ZYDIS_REGISTER_NONE)
						return false;
					if (insn->operands[1].mem.index != ZYDIS_REGISTER_NONE)
						return false;

					if (insn->operands[0].size != 32)
						return false;
				}

				if constexpr (!isx64)
				{
					size_t offset = insn->getFirstSegmentOffset(ZYDIS_INSTR_SEGMENT_DISPLACEMENT);
					bool isReloc = false;

					// Remove any relocation if needed
					if (app() && app()->isRelocationPresent(toRva(insn->address) + offset))
					{
						app()->removeRelocation(toRva(insn->address) + offset);
						isReloc = true;
					}

					u32 rva = isReloc ? toRva(insn->operands[1].mem.disp.value) : insn->operands[1].mem.disp.value;

					u16 upper = (u16)(rva >> 16);
					u16 lower = (u16)(rva & 0xffff);

					// Temporary registers for use.
					const static x86::Gpd _r32ss[] =
					{
						x86::regs::ebx,
						x86::regs::ecx,
						x86::regs::edx
					};

					x86::Gp tmpGp = x86::regs::eax;
					x86::Reg tmpGpReg(tmpGp);

					while (dst == tmpGp.r32())
					{
						tmpGp = _r32ss[util::genRandInteger<u32>(0, ASMJIT_ARRAY_SIZE(_r32ss))];
						tmpGpReg = tmpGp;
					}

					x86::Gpw tmpGpW = x86::gpw(tmpGpReg.id());
					x86::GpbHi tmpGpHi = x86::gpb_hi(tmpGpReg.id());
					x86::GpbLo tmpGpLo = x86::gpb_lo(tmpGpReg.id());

					//printf("*** LOWER: 0x%x **\n", lower);
					//printf("*** UPPER: 0x%x **\n", upper);

					u16 keyUp = util::genRandInteger<u16>();
					u16 keyLow = util::genRandInteger<u16>();

					if (upper != 0)
					{
						upper = ~upper;
						upper ^= keyUp;
						upper = _byteswap_ushort(upper);
					}

					lower = _byteswap_ushort(lower);
					lower = ~lower;
					lower ^= keyLow;

					cc->pushfd();

					// Load lower portion
					cc->sub(stackReg, sizeof(u16));
					cc->mov(x86::word_ptr(stackReg), lower);


					// Load and decrypt the upper 16 bits
					x86::Reg dstReg(dst);
					x86::Gpw dstW = x86::gpw(dstReg.id());
					x86::Gpd dstDw = x86::gpd(dstReg.id());

					cc->mov(dstDw, upper);

					if (upper != 0)
					{
						// EDI/ESI/EBP aren't registers with 16bit subsections that can be used 
						// to swap the bytes. I use the easy way out and transfer control to
						// a temp register where the subsections needed are present.
						bool unsupported = false;

						x86::GpbHi dstHi = x86::gpb_hi(dstReg.id());
						x86::GpbLo dstLo = x86::gpb_lo(dstReg.id());

						// TODO: Do something better
						if (dstReg == x86::regs::edi ||
							dstReg == x86::regs::esi ||
							dstReg == x86::regs::ebp)
						{
							unsupported = true;

							cc->push(tmpGp);
							cc->mov(tmpGp, dstDw);

							dstHi = tmpGpHi;
							dstLo = tmpGpLo;
						}

						// BSWAP does not work on 8bit operands
						cc->xchg(dstHi, dstLo);
						if (unsupported)
							cc->xchg(tmpGp, dstDw);
						cc->xor_(dstW, keyUp);
						cc->not_(dstW);
						cc->shl(dstDw, 16);

						if (unsupported)
						{
							cc->pop(tmpGp);
						}
					}


					// Decrypt the lower portion
					constexpr size_t stackOffset = sizeof(u32);

					cc->push(tmpGp);
					cc->xor_(tmpGp, tmpGp);
					cc->mov(tmpGpW, x86::word_ptr(stackReg, stackOffset));
					cc->xor_(tmpGpW, keyLow);
					cc->not_(tmpGpW);
					cc->xchg(tmpGpLo, tmpGpHi);
					cc->xchg(tmpGpW, x86::word_ptr(stackReg, stackOffset));
					cc->pop(tmpGp);

					// OR the two values
					cc->mov(dstW, x86::word_ptr(stackReg));

					// Clean up
					cc->add(stackReg, sizeof(u16));

					if (isReloc)
					{
						cc->push(tmpGp);

						if (isDll)
						{
							// Relocate base address
							makeRelocation(0x1);
							cc->mov(tmpGp, app()->getBaseAddress());
						}
						else
						{
							fetchPeb(tmpGp);
							cc->mov(tmpGp, x86::dword_ptr(tmpGp, 8));
						}

						cc->xchg(x86::dword_ptr(stackReg), tmpGp);
						cc->add(dst, x86::dword_ptr(stackReg));
						cc->xchg(x86::dword_ptr(stackReg), tmpGp);
						cc->pop(tmpGp);
					}

					cc->push(x86::dword_ptr(dst));
					cc->pop(dst);

					cc->popfd();

					return true;
				}
				else
				{
					u64 absolute = Disassembler::instance()->calcAbsolute(&insn->decoded, &insn->operands[1], insn->address);
					u32 rva = toRva(absolute);
					u32 key = util::genRandInteger<u32>();
					u32 rots = util::genRandInteger<u32>(1, 31);

					x86::Reg dstReg(dst);
					x86::Gpd dstDw = x86::gpd(dstReg.id());
					x86::Gpq dstQw = x86::gpq(dstReg.id());

					rva ^= key;
					rva = _rotl(rva, rots);
					rva = ~rva;
					rva = _byteswap_ulong(rva);

					cc->mov(dstDw, rva);
					cc->bswap(dstDw);
					cc->not_(dstDw);
					cc->ror(dstDw, rots);
					cc->xor_(dstDw, key);
					cc->push(dst);

					if (app()->getImage().isDllOrSystemFile())
					{
						cc->push(x86::regs::rax);
						makeRelocation(0x2);
						cc->mov(x86::regs::rax, app()->getBaseAddress());
						cc->add(x86::qword_ptr(stackReg, 8), x86::regs::rax);
						cc->pop(x86::regs::rax);
					}
					else
					{
						cc->push(x86::regs::rax);
						fetchPeb(x86::regs::rax);
						cc->mov(x86::regs::rax, x86::qword_ptr(x86::regs::rax, 0x10));
						cc->add(x86::qword_ptr(stackReg, 8), x86::regs::rax);
						cc->pop(x86::regs::rax);
					}

					cc->pop(dst);
					cc->mov(dst, x86::ptr(dstQw, 0, dstReg.size()));
					return true;
				}
			}
			else
			{
				return false;
			}
		}
	}

	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY))
	{
		if (insn->operands[0].mem.segment != ZYDIS_REGISTER_DS)
			return false;

		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_IMMEDIATE))
		{
			if (isx64 && insn->operands[1].size == 32)
			{
				if (insn->operands[0].mem.base != ZYDIS_REGISTER_RIP)
					return false;

				u64 dst = Disassembler::instance()->calcAbsolute(insn);
				u32 dstRva = toRva(dst);
				u32 imm = insn->operands[1].imm.value.u;

				u32 dstKey = util::genRandInteger<u32>();
				u32 dstKey2 = util::genRandInteger<u32>();

				u32 immKey = util::genRandInteger<u32>();
				u32 immKey2 = util::genRandInteger<u32>();
				u32 rots = util::genRandInteger<u32>(1, 31);

				imm ^= immKey;
				imm = ~imm;
				imm ^= immKey2;
				imm = _rotl(imm, rots);

				dstRva ^= dstKey;
				dstRva = _byteswap_ulong(dstRva);
				dstRva ^= dstKey2;
				dstRva = ~dstRva;

				auto _rax = x86::regs::rax;

				cc->push(_rax);
				cc->sub(stackReg, sizeof(u64));

				cc->mov(x86::regs::eax, imm);
				cc->ror(x86::regs::eax, rots);
				cc->xor_(x86::regs::eax, immKey2);
				cc->not_(x86::regs::eax);
				cc->xor_(x86::regs::eax, immKey);
				cc->xchg(x86::qword_ptr(stackReg), _rax);
				
				// Decrypt RVA
				cc->mov(x86::regs::eax, dstRva);
				cc->not_(x86::regs::eax);
				cc->xor_(x86::regs::eax, dstKey2);
				cc->bswap(x86::regs::eax);
				cc->xor_(x86::regs::eax, dstKey);

				cc->push(_rax);

				if (app()->getImage().isDllOrSystemFile())
				{
					// Load image base and relocate manually
					makeRelocation(0x2);
					cc->movabs(_rax, app()->getBaseAddress());
				}
				else
				{
					// Use PEB to resolve current base address
					fetchPeb(_rax);
					cc->mov(_rax, x86::qword_ptr(_rax, 0x10));
				}

				cc->add(x86::qword_ptr(stackReg), _rax);
				cc->pop(_rax);

				// rax now holds the pointer to load the immediate into.
				cc->push(x86::regs::rcx);
				cc->xchg(x86::regs::rcx, x86::qword_ptr(stackReg, sizeof(u64)));
				cc->mov(x86::qword_ptr(_rax), x86::regs::rcx);
				cc->pop(x86::regs::rcx);
				cc->add(stackReg, sizeof(u64));
				cc->pop(_rax);

				return true;
			}
			else
			{
				if (insn->operands[0].mem.disp.has_displacement &&
					insn->operands[1].size == 32)
				{
					if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
						return false;
					if (insn->operands[0].mem.index != ZYDIS_REGISTER_NONE)
						return false;

					ZydisInstructionSegments segs;
					ZydisGetInstructionSegments(&insn->decoded, &segs);
					bool isReloc = false;
					bool isImmReloc = false;

					for (int i = 0; i < segs.count; ++i)
					{
						auto seg = segs.segments[i];

						if (seg.type != ZYDIS_INSTR_SEGMENT_DISPLACEMENT &&
							seg.type != ZYDIS_INSTR_SEGMENT_IMMEDIATE)
							continue;

						if (app()->isRelocationPresent(toRva(insn->address) + seg.offset))
						{
							app()->removeRelocation(toRva(insn->address) + seg.offset);

							if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
								isReloc = true;
							else
								isImmReloc = true;
						}
					}

					u32 val = isReloc ? toRva(insn->operands[0].mem.disp.value) : insn->operands[0].mem.disp.value;
					u32 imm = isImmReloc ? toRva(insn->operands[1].imm.value.u) : insn->operands[1].imm.value.u;
					u32 valKey = util::genRandInteger<u32>();
					u32 immKey = util::genRandInteger<u32>();

					imm = ~imm;
					imm ^= immKey;
					imm = _byteswap_ulong(imm);

					val -= (valKey >> 1);
					val = ~val;
					val = _rotl(val, 8);

					cc->pushfd();

					cc->push(val);
					cc->ror(x86::dword_ptr(stackReg), 8);
					cc->not_(x86::dword_ptr(stackReg));
					cc->add(x86::dword_ptr(stackReg), valKey >> 1);
					// Preserve EAX
					cc->push(x86::regs::eax);

					if (isReloc)
					{
						if (isDll)
						{
							// Relocate base address
							makeRelocation(0x1);
							cc->mov(x86::regs::eax, app()->getBaseAddress());
							cc->add(x86::dword_ptr(stackReg, 4), x86::regs::eax);
						}
						else
						{
							fetchPeb(x86::regs::eax);
							cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax, 8));
							cc->add(x86::dword_ptr(stackReg, 4), x86::regs::eax);
						}
					}
					
					if (isImmReloc)
						cc->push(x86::regs::eax);

					cc->mov(x86::regs::eax, imm);
					cc->bswap(x86::regs::eax);
					cc->xor_(x86::regs::eax, immKey);
					cc->not_(x86::regs::eax);
					
					if (isImmReloc)
					{
						cc->add(x86::dword_ptr(stackReg), x86::regs::eax);
						cc->pop(x86::regs::eax);
					}
					
					// EAX now holds the decrypted imm.
					cc->push(x86::regs::ebx);
					cc->mov(x86::regs::ebx, x86::dword_ptr(stackReg, 8));
					cc->push(x86::regs::eax);
					cc->pop(x86::dword_ptr(x86::regs::ebx));
					cc->pop(x86::regs::ebx);
					cc->pop(x86::regs::eax);
					
					cc->add(x86::regs::esp, sizeof(u32));

					cc->popfd();

					return true;
				}
			}
		}
		
		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_REGISTER))
		{
			// Segment registers not handled yet
			if (insn->operands[1].reg.value >= ZYDIS_REGISTER_ES &&
				insn->operands[1].reg.value <= ZYDIS_REGISTER_GS)
			{
				return false;
			}


			// Only 32bit operands
			if (insn->operands[0].mem.disp.has_displacement &&
				insn->operands[1].size == 32)
			{
				if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
					return false;
				if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
					return false;
				if (insn->operands[0].mem.index != ZYDIS_REGISTER_NONE)
					return false;

				size_t offset = insn->getFirstSegmentOffset(ZYDIS_INSTR_SEGMENT_DISPLACEMENT);
				bool isReloc = false;

				// Remove any relocation if needed
				if (app() && app()->isRelocationPresent(toRva(insn->address) + offset))
				{
					app()->removeRelocation(toRva(insn->address) + offset);
					isReloc = true;
				}

				u32 val = toRva(insn->operands[0].mem.disp.value);
				u32 valKey = util::genRandInteger<u32>();
				auto src = x86util::getAsmRegAny(insn->operands[1].reg.value);

				val += (valKey >> 1);
				val = ~val;
				val = _rotl(val, 8);

				cc->pushfd();
				// Push base
				makeRelocation(0x1);
				cc->push(app()->getBaseAddress());

				cc->push(val);
				cc->ror(x86::dword_ptr(stackReg), 8);
				cc->not_(x86::dword_ptr(stackReg));
				cc->sub(x86::dword_ptr(stackReg), valKey >> 1);

				// Preserve
				cc->push(x86::regs::ebp);

				cc->mov(x86::regs::ebp, x86::dword_ptr(stackReg, 4));
				// Resolve RVA
				cc->add(x86::regs::ebp, x86::dword_ptr(stackReg, 8));
				// Load
				cc->mov(x86::dword_ptr(x86::regs::ebp), src);

				// Cleanup
				cc->pop(x86::regs::ebp);
				cc->add(stackReg, sizeof(u64));

				cc->popfd();

				return true;
			}
		}
	}


	return false;
}

MUT_TEMPLATE bool perses::MutationLightSchema<BitSize>::handleXor(instruction_t* insn)
{
	//return false;

	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_REGISTER) &&
		(insn->operands[1].size == 32 || insn->operands[1].size == 64))
	{
		auto dst = x86util::getAsmRegAny(insn->operands[0].reg.value);

		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_REGISTER))
		{
			auto val = x86util::getAsmRegAny(insn->operands[1].reg.value);

			if (dst == val)
				return false;

			genXor(dst, val);
			return true;
		}

		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_IMMEDIATE))
		{
			auto val = insn->operands[1].imm.value.u;

			// Play it safe for potential relocated immediates
			// We can handle these, but for now, ignore.
			if constexpr (BitSize == PERSES_32BIT)
			{
				if (val >= app()->getBaseAddress() &&
					val <= (app()->getBaseAddress() + app()->getImage().getPEHdr().calcSizeOfImage()))
				{
					return false;
				}
			}

			genXorImm(dst, val);
			return true;
		}

		//printf("***** Generated XOR *****\n");

		return false;
	}
	

	return false;
}

MUT_TEMPLATE bool perses::MutationLightSchema<BitSize>::handleAdd(instruction_t* insn)
{
	if (insn->isOperandType(0, ZYDIS_OPERAND_TYPE_REGISTER) &&
		insn->operands[1].size == 32)
	{
		if (insn->operands[0].reg.value == ZYDIS_REGISTER_ESP ||
			insn->operands[0].reg.value == ZYDIS_REGISTER_RSP)
			return false;

		auto dst = x86util::getAsmRegAny(insn->operands[0].reg.value);
	
		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_REGISTER))
		{
			auto val = x86util::getAsmRegAny(insn->operands[1].reg.value);
			
			if (dst == val)
				return false;

			genAdd(dst, val);
			return true;
		}
		
		if (insn->isOperandType(1, ZYDIS_OPERAND_TYPE_IMMEDIATE))
		{
			auto val = insn->operands[1].imm.value.u;

			// Play it safe for potential relocated immediates
			// We can handle these, but for now, ignore.
			if constexpr (BitSize == PERSES_32BIT)
			{
				if (val >= app()->getBaseAddress() &&
					val <= (app()->getBaseAddress() + app()->getImage().getPEHdr().calcSizeOfImage()))
				{
					return false;
				}
			}
			

			genAddImm(dst, val);
			return true;
		}

		//printf("Generated ADD\n");

		return false;
	}

	return false;
}

MUT_TEMPLATE bool perses::MutationLightSchema<BitSize>::handleRelInstruction(instruction_t* insn)
{
	bool isImm = insn->isOperandType(0, ZYDIS_OPERAND_TYPE_IMMEDIATE);
	bool isMem = insn->isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY);


	assembler::x86::Assembler* cc = this->getCompiler();
	u64 absolute = Disassembler::instance()->calcAbsolute(insn);

	if (isImm)
	{
		// DO NOT process imm JMPs if they lye in our routine's range.
		if (absolute > _rtnBegin && absolute < _rtnEnd)
		{
			// I've never seen this happen but I'll get around to it if it does.
			if (insn->isMnemonic(ZYDIS_MNEMONIC_CALL))
			{
				return false;
				PERSES_THROW("CALL found in the routine's range, implement functionality!");
			}

#ifdef PERSES_VERBOSE
			// printf("******** SKIPPING RELATIVE IN ROUTINE RANGE **********\n");
#endif
			return false;
		}

		// UNCOMMENT IF NEEDED TO REMOVE CALL/JMP OBFUSCATION
		if (insn->decoded.opcode == 0xe8)
		{
		//	cc->call(absolute);
		//	return true;
		}

		if (insn->decoded.opcode == 0xe9)
		{
		//	cc->jmp(absolute);
		//	return true;
		}
	}

	//return false;

	if (!isImm && !isMem)
		return false;

	if (insn->isMnemonic(ZYDIS_MNEMONIC_CALL))
	{
		if (isImm)
		{
			if constexpr (BitSize == PERSES_64BIT)
			{
				u64 callDst = absolute;
				u64 cryptDst = toRva(callDst);

				u32 key = util::genRandInteger<int>();
				u32 key2 = util::genRandInteger<int>();
				u32 rots = util::genRandInteger<u32>(1, 48);

				cryptDst = _byteswap_uint64(cryptDst);
				cryptDst ^= key2;
				cryptDst = _rotr64(cryptDst, rots);
				cryptDst ^= key;
				cryptDst = ~cryptDst;

				Label label = cc->newLabel();

				cc->sub(x86::regs::rsp, 8);
				cc->push(x86::regs::r15);
				cc->lea(x86::regs::r15, x86::ptr(label));
				cc->mov(x86::qword_ptr(x86::regs::rsp, 8), x86::regs::r15);
				cc->pop(x86::regs::r15);

				cc->sub(x86::regs::rsp, 8);
				cc->push(x86::regs::r15);

				// Decrypt the RVA
				cc->movabs(x86::regs::r15, cryptDst);
				cc->not_(x86::regs::r15);
				cc->mov(x86::qword_ptr(x86::regs::rsp, 8), key);
				cc->xor_(x86::regs::r15, x86::qword_ptr(x86::regs::rsp, 8));
				cc->rol(x86::regs::r15, rots);
				cc->mov(x86::qword_ptr(x86::regs::rsp, 8), key2);
				cc->xor_(x86::regs::r15, x86::qword_ptr(x86::regs::rsp, 8));
				cc->bswap(x86::regs::r15);
				cc->xchg(x86::regs::r15, x86::qword_ptr(x86::regs::rsp, 8));
				
				if (true)// app()->getImage().isDllOrSystemFile())
				{
					// Load image base and relocate manually
					makeRelocation(0x2);
					cc->movabs(x86::regs::r15, app()->getBaseAddress());
				}
				else
				{
					// Use PEB to resolve current base address
					fetchPeb(x86::regs::r15);
					cc->mov(x86::regs::r15, x86::qword_ptr(x86::regs::r15, 0x10));
				}

				cc->add(x86::qword_ptr(x86::regs::rsp, 8), x86::regs::r15);

				// Restore R15.
				cc->pop(x86::regs::r15);


				// Jump to a random RET if possible
				if (!gs_retGadgets.empty())
					cc->jmp(gs_retGadgets[rand() % gs_retGadgets.size()]);
				else
					cc->ret();

				cc->bind(label);
				return true;
			}
			else
			{
				u32 callDst = (u32)absolute;
				u32 cryptDst = toRva(callDst);

				u32 key = util::genRandInteger<u32>();
				u32 key2 = util::genRandInteger<u32>();
				u32 rots = util::genRandInteger<u32>(1, 18);

				cryptDst = _byteswap_ulong(cryptDst);
				cryptDst ^= key2;
				cryptDst = _rotl(cryptDst, rots);
				cryptDst ^= key;
				cryptDst = ~cryptDst;

				Label label = cc->newLabel();

				cc->sub(x86::regs::esp, sizeof(u32));
				cc->push(x86::regs::eax);
				makeRelocation(0x2);
				cc->lea(x86::regs::eax, x86::dword_ptr(label));
				cc->mov(x86::dword_ptr(x86::regs::esp, 4), x86::regs::eax);
				cc->pop(x86::regs::eax);
				cc->push(cryptDst);
				cc->pushfd();
				cc->not_(x86::dword_ptr(x86::regs::esp, 4));
				cc->xor_(x86::dword_ptr(x86::regs::esp, 4), key);
				cc->ror(x86::dword_ptr(x86::regs::esp, 4), rots);
				cc->xor_(x86::dword_ptr(x86::regs::esp, 4), key2);
				cc->popfd();
				cc->push(x86::regs::eax);
				cc->xchg(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 4));
				cc->bswap(x86::regs::eax);
				cc->xchg(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 4));
				cc->pop(x86::regs::eax);
				makeRelocation(0x3);
				cc->add(x86::dword_ptr(x86::regs::esp), app()->getBaseAddress());
				
				// Jump to a random RET if possible
				if (!gs_retGadgets.empty())
					cc->jmp((u32)gs_retGadgets[rand() % gs_retGadgets.size()]);
				else
					cc->ret();

				cc->bind(label);

				return true;
			}
		}


		if (isMem)
		{
			if constexpr (BitSize == PERSES_64BIT)
			{
				if (insn->operands[0].mem.disp.has_displacement)
				{
					if (insn->operands[0].mem.base != ZYDIS_REGISTER_RIP)
						return false;

					u64 callDst = absolute;
					u64 cryptDst = toRva(callDst);

					u32 key = util::genRandInteger<int>();
					u32 key2 = util::genRandInteger<int>();
					u32 rots = util::genRandInteger<u32>(1, 48);

					cryptDst = _byteswap_uint64(cryptDst);
					cryptDst ^= key2;
					cryptDst = _rotr64(cryptDst, rots);
					cryptDst ^= key;
					cryptDst = ~cryptDst;

					Label label = cc->newLabel();

					cc->lea(x86::regs::rax, x86::ptr(label));
					cc->push(x86::regs::rax);
					cc->sub(x86::regs::rsp, 8);
					cc->movabs(x86::regs::rax, cryptDst);
					// Decrypt the RVA
					cc->not_(x86::regs::rax);
					cc->mov(x86::qword_ptr(x86::regs::rsp), key);
					cc->xor_(x86::regs::rax, x86::qword_ptr(x86::regs::rsp));
					cc->rol(x86::regs::rax, rots);
					cc->mov(x86::qword_ptr(x86::regs::rsp), key2);
					cc->xor_(x86::regs::rax, x86::qword_ptr(x86::regs::rsp));
					cc->bswap(x86::regs::rax);
					cc->xchg(x86::regs::rax, x86::qword_ptr(x86::regs::rsp));

					if (app()->getImage().isDllOrSystemFile())
					{
						// Load image base and relocate manually
						makeRelocation(0x2);
						cc->movabs(x86::regs::rax, app()->getBaseAddress());
					}
					else
					{
						// Use PEB to resolve current base address
						fetchPeb(x86::regs::rax);
						cc->mov(x86::regs::rax, x86::qword_ptr(x86::regs::rax, 0x10));
					}

					cc->add(x86::qword_ptr(x86::regs::rsp), x86::regs::rax);
					cc->xchg(x86::qword_ptr(x86::regs::rsp), x86::regs::rax);
					cc->mov(x86::regs::rax, x86::qword_ptr(x86::regs::rax));
					cc->xchg(x86::qword_ptr(x86::regs::rsp), x86::regs::rax);

					// Jump to a random RET if possible
					if (!gs_retGadgets.empty())
						cc->jmp(gs_retGadgets[rand() % gs_retGadgets.size()]);
					else
						cc->ret();

					cc->bind(label);
					return true;
				}
			}
			else
			{
				// printf("absolute: 0x%x\n", (u32)absolute);

				if (insn->operands[0].mem.disp.has_displacement)
				{
					if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
						return false;

					u32 offset = insn->getFirstSegmentOffset(ZYDIS_INSTR_SEGMENT_DISPLACEMENT);
					bool isRelocatable = app()->isRelocationPresent((insn->address - app()->getBaseAddress()) + offset);

					if (isRelocatable)
					{
						// We need to remove/ignore the relocation so that our code doesn't break when the PE ldr. attempts to
						// process the reloc. directory.
						app()->removeRelocation((insn->address - app()->getBaseAddress()) + offset);
					}

					u32 disp = insn->operands[0].mem.disp.value;
					u32 rva = toRva(disp);
					u32 key = util::genRandInteger<u32>();
					Label label = cc->newLabel();

					rva = ~rva;
					rva ^= key;

					// Generate junk code randomly
					bool j = false;
					if ((key & 0xf) < 7)
						cc->lahf();
					else
						j = true;

					// Generate relocation for the return address
					makeRelocation(0x2);
					cc->lea(x86::regs::eax, x86::dword_ptr(label));
					cc->push(x86::regs::eax);


					cc->push(rva);
					cc->xor_(x86::dword_ptr(x86::regs::esp), key);
					cc->not_(x86::dword_ptr(x86::regs::esp));

					if (app()->getImage().isDllOrSystemFile())
					{
						makeRelocation(0x1);
						cc->mov(x86::regs::eax, app()->getBaseAddress());
					}
					else
					{
						fetchPeb(x86::regs::eax);
						cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax, 8));
					}

					// Add the base address, and generate a relocation for runtime
					cc->add(x86::dword_ptr(x86::regs::esp), x86::regs::eax);
					cc->xchg(x86::dword_ptr(x86::regs::esp), x86::regs::eax);
					cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax));
					cc->xchg(x86::dword_ptr(x86::regs::esp), x86::regs::eax);

					// Generate junk code randomly
					if (j)
						cc->sahf();

					// Jump to a random RET if possible
					if (!gs_retGadgets.empty())
						cc->jmp((u32)gs_retGadgets[rand() % gs_retGadgets.size()]);
					else
						cc->ret();
					cc->bind(label);

					return true;
				}
			}
		}
	}
	
	if (insn->isMnemonic(ZYDIS_MNEMONIC_JMP) && isImm && insn->decoded.opcode == 0xE9)
	{
		if constexpr (BitSize == 64)
		{
			u64 callDst = (u64)absolute;
			u64 cryptDst = callDst - app()->getBaseAddress();


			cc->sub(x86::regs::rsp, sizeof(u64));
			cc->mov(x86::qword_ptr(x86::regs::rsp), cryptDst);

			cc->push(x86::regs::rax);
			// Resolve RVA
			makeRelocation(0x2);
			cc->mov(x86::regs::rax, app()->getBaseAddress());
			cc->add(x86::qword_ptr(x86::regs::rsp, 8), x86::regs::rax);
			cc->pop(x86::regs::rax);

			// Jump to a random RET if possible
			if (!gs_retGadgets.empty())
				cc->jmp(gs_retGadgets[rand() % gs_retGadgets.size()]);
			else
				cc->ret();

			return true;
		}
		else
		{
			u32 callDst = (u32)absolute;
			u32 cryptDst = callDst - app()->getBaseAddress();

			u32 key = util::genRandInteger<u32>();
			u32 key2 = util::genRandInteger<u32>();
			u32 rots = util::genRandInteger<u32>(1, 18);
			u32 rots2 = util::genRandInteger<u32>(3, 12);

			cryptDst = _rotl(cryptDst, rots);
			cryptDst ^= key;
			cryptDst = _rotr(cryptDst, rots2);
			cryptDst ^= key2;

			cc->push(cryptDst);
			cc->xor_(x86::dword_ptr(x86::regs::esp), key2);
			cc->rol(x86::dword_ptr(x86::regs::esp), rots2);
			cc->xor_(x86::dword_ptr(x86::regs::esp), key);
			cc->ror(x86::dword_ptr(x86::regs::esp), rots);

			cc->push(x86::regs::eax);
			// Resolve RVA
			makeRelocation(0x1);
			cc->mov(x86::regs::eax, app()->getBaseAddress());
			cc->add(x86::qword_ptr(x86::regs::esp, 4), x86::regs::eax);
			cc->pop(x86::regs::eax);


			// Jump to a random RET if possible
			if (!gs_retGadgets.empty())
				cc->jmp((u32)gs_retGadgets[rand() % gs_retGadgets.size()]);
			else
				cc->ret();

			return true;
		}
	}
	// this->getCompiler()->call(static_cast<u32>(absolute));

	return false;
}

MUT_TEMPLATE X86BinaryApplication<BitSize>* MutationLightSchema<BitSize>::app()
{
	return (X86BinaryApplication<BitSize>*)_app;
}

MUT_TEMPLATE void perses::MutationLightSchema<BitSize>::makeRelocation(int offset, bool relative, u64 absolute)
{
	static int relocIdx = 0;

	Label reloc = this->getCompiler()->newNamedLabel(fmt::format("RELOC_{}", relocIdx++).c_str());

	this->getCompiler()->bind(reloc);

	if (!relative)
		_relocEntryList.emplace_back(0, offset, 0, 0ull);
	else
		_relocEntryList.emplace_back(_streamOffset, offset, _currentInstruction->decoded.length, absolute);
}

MUT_TEMPLATE u32 MutationLightSchema<BitSize>::toRva(uptr address)
{
	return (address - app()->getBaseAddress());
}

MUT_TEMPLATE void MutationLightSchema<BitSize>::fetchPeb(x86::Gp dst)
{
	assembler::x86::Assembler* cc = this->getCompiler();

	if constexpr (BitSize == PERSES_64BIT)
	{
		u64 imm = 0x60;
		u32 rots = util::genRandInteger<u32>(1, 64);

		imm = _byteswap_uint64(imm);
		imm = _rotr64(imm, rots);

		cc->mov(dst, imm);
		cc->rol(dst, rots);
		cc->bswap(dst);

		assembler::x86::Mem peb(x86::qword_ptr(dst));
		peb.setSegment(x86::regs::gs);

		cc->mov(dst, peb);
	}
	else
	{
		u32 imm = offsetof(NT_TIB, Self);
		u32 key = util::genRandInteger<u32>();
		bool rot = (key & 1) != 0;

		imm ^= key;
		imm = _byteswap_ulong(imm);

		if (rot) imm = _rotr(imm, key & 0xf);

		cc->mov(dst, imm);
		if (rot) cc->rol(dst, key & 0xf);
		cc->bswap(dst);
		cc->xor_(dst, key);
		

		assembler::x86::Mem peb(x86::dword_ptr(dst));
		peb.setSegment(x86::regs::fs);

		cc->mov(dst, peb);
	}
}

MUT_TEMPLATE bool perses::MutationLightSchema<BitSize>::recoverJumpTable(instruction_t* insn)
{
	if (!app())
		return false;

	x86::Assembler* cc = this->getCompiler();
	assembler::x86::Gp stackReg;


	if constexpr (BitSize == PERSES_64BIT)
	{
		stackReg = x86::regs::rsp;
	}
	else
	{
		stackReg = x86::regs::esp;
	}

	// NOTE: This was only tested on MSVC (VS2022), so this may have to be tweaked
	// to support the output of different compilers.

	int jumpTableSize = 0;

	//
	// Try to find jump table size, note that there can be another jump table right next to another individual jump table,
	// this is a first resort to calculating it, the last resort is in x86BinaryApplication::inquireJumpTable.
	auto it = std::find_if(_rtn->begin(), _rtn->end(), [insn](instruction_t& i) { return insn->address == i.address; });
	if (it != _rtn->end())
	{
		int inCount = 0;

		for (auto i = it; i != _rtn->begin(); --i)
		{
			if (inCount > 10)
				break;

			if (i->isMnemonic(ZYDIS_MNEMONIC_CMP))
			{
				if (i->isOperandType(1, ZYDIS_OPERAND_TYPE_IMMEDIATE))
				{
					jumpTableSize = i->operands[1].imm.value.u + 1;
					break;
				}
			}

			++inCount;
		}
	}

	if constexpr (BitSize == PERSES_32BIT)
	{
		if (!insn->isOperandType(0, ZYDIS_OPERAND_TYPE_MEMORY) || !insn->operands[0].mem.disp.has_displacement)
			return false;

		std::vector<JumpTableEntry> entries { };
		if (!app()->inquireJumpTable(insn, _rtnBegin, _rtnEnd, jumpTableSize, entries))
			return false;


		// Sanity check. This may need to be changed - personally, I've never seen a jump table with less than 6 entries
		//if (entries.size() >= 4)
		{
			logger()->info("[JUMP TABLE] Handling potential jump table with {} entries.", entries.size());
			_jumpTables.insert(_jumpTables.end(), entries.begin(), entries.end());
		}

		// Remove existing relocations
		u32 offset = insn->getFirstSegmentOffset(ZYDIS_INSTR_SEGMENT_DISPLACEMENT);
		bool isRelocatable = app()->isRelocationPresent((insn->address - app()->getBaseAddress()) + offset);

		if (isRelocatable)
		{
			// We need to remove/ignore the relocation so that our code doesn't break when the PE ldr. attempts to
			// process the reloc. directory.
			app()->removeRelocation((insn->address - app()->getBaseAddress()) + offset);
		}
		
		//x86::Mem mem;
		//if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
		//{
		//	x86::Gp base = x86util::getAsmRegAny(insn->operands[0].mem.base);
		//	x86::Gp index = x86util::getAsmRegAny(insn->operands[0].mem.index);
		//	mem.setBase(base);
		//	mem.setIndex(index);
		//	mem.setShift(insn->operands[0].mem.scale >> 1);
		//}
		//else
		//{
		//	return false;
		//}
		//cc->jmp(mem);
		//return true;

		// JMP encryption
		u64 dst = insn->operands[0].mem.disp.value;

		u32 key = util::genRandInteger<u32>();
		u32 swap = toRva(dst);
		
		swap ^= key;
		swap = _byteswap_ulong(swap);

		cc->push(util::genRandInteger<u32>());
		cc->pushfd();
		cc->push(x86::regs::eax);

		cc->mov(x86::regs::eax, swap);
		cc->bswap(x86::regs::eax);
		cc->xor_(x86::regs::eax, key);
		cc->mov(x86::dword_ptr(x86::regs::esp, 8), x86::regs::eax);
		cc->pop(x86::regs::eax);
		
		// Translate RVA to VA
		makeRelocation(0x4);
		cc->add(x86::dword_ptr(x86::regs::esp, 4), app()->getBaseAddress());

		if (insn->operands[0].mem.base != ZYDIS_REGISTER_NONE)
		{
			x86::Gp base = x86util::getAsmRegAny(insn->operands[0].mem.base);
			cc->add(x86::dword_ptr(x86::regs::esp, 4), base);
		}

		if (insn->operands[0].mem.index != ZYDIS_REGISTER_NONE)
		{
			x86::Gp index = x86util::getAsmRegAny(insn->operands[0].mem.index);

			if (insn->operands[0].mem.scale == 4)
			{
				cc->push(index);
				cc->shl(index, 2);
				cc->add(x86::dword_ptr(x86::regs::esp, 4+index.size()), index);
				cc->pop(index);
			}
			else
			{
				if (insn->operands[0].mem.scale == 0)
					cc->add(x86::dword_ptr(x86::regs::esp, 4), index);
			}
		}

		// Load the memory offset
		cc->push(x86::regs::eax);
		cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 8));
		cc->mov(x86::regs::eax, x86::dword_ptr(x86::regs::eax));
		cc->xchg(x86::regs::eax, x86::dword_ptr(x86::regs::esp, 8));
		cc->pop(x86::regs::eax);
		cc->popfd();
		// Jump to a random RET if possible
		if (!gs_retGadgets.empty())
			cc->jmp((u32)gs_retGadgets[rand() % gs_retGadgets.size()]);
		else
			cc->ret();

		return true;
	}
	else
	{
		std::vector<JumpTableEntry> entries { };
		if (!app()->inquireJumpTable(insn, _rtnBegin, _rtnEnd, jumpTableSize, entries))
			return false;

		u32 scale = (u32)insn->operands[1].mem.scale;

		if (!entries.empty())
		{
			logger()->info("[JUMP TABLE] Handling potential jump table with {} entries.", entries.size());
			_jumpTables.insert(_jumpTables.end(), entries.begin(), entries.end());
		}

		ZydisRegister base = insn->operands[1].mem.base;
		ZydisRegister index = insn->operands[1].mem.index;
		x86::Gp dstReg = x86util::getAsmRegAny(insn->operands[0].reg.value);
		x86::Gpd dstRegDw = x86::gpd(dstReg.id());
		x86::Gpq dstRegQw = x86::gpq(dstReg.id());
		x86::Gp baseReg = x86util::getAsmRegAny(base);
		x86::Gp indexReg = x86util::getAsmRegAny(index);

		u32 val = insn->operands[1].mem.disp.value;
		u32 key = util::genRandInteger<u32>();
		u32 key2 = util::genRandInteger<u32>();
		
		val ^= key;
		val = _byteswap_ulong(val);
		val = ~val;

		cc->push(dstReg);

		cc->mov(dstReg, val);
		cc->not_(dstRegDw);
		cc->bswap(dstRegDw);
		cc->xor_(dstRegDw, key);
		cc->add(dstRegQw, baseReg);
		cc->xchg(dstRegQw, x86::qword_ptr(stackReg));

		if (dstRegQw != indexReg)
			cc->mov(dstRegQw, indexReg);
		
		if (scale != 4)
		{
			PERSES_THROW("Unexpected scale in MutationLightSchema::recoverJumpTable.");
			return false;
		}

		// Apply the scale
		cc->shl(dstReg, 2);
		cc->add(x86::qword_ptr(stackReg), dstRegQw);
		cc->pop(dstReg);
		cc->mov(dstReg, x86::qword_ptr(dstRegQw));

		return true;
	}

	return false;
}

MUT_TEMPLATE void MutationLightSchema<BitSize>::writeJcc(ZydisDecodedInstruction* instr, assembler::Label& lbl)
{
	switch (instr->mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
		this->getCompiler()->jnbe(lbl);
		break;
	case ZYDIS_MNEMONIC_JB:
		this->getCompiler()->jb(lbl);
		break;
	case ZYDIS_MNEMONIC_JBE:
		this->getCompiler()->jbe(lbl);
		break;
	case ZYDIS_MNEMONIC_JECXZ:
		this->getCompiler()->jecxz(lbl);
		break;
	case ZYDIS_MNEMONIC_JL:
		this->getCompiler()->jl(lbl);
		break;
	case ZYDIS_MNEMONIC_JLE:
		this->getCompiler()->jle(lbl);
		break;
	case ZYDIS_MNEMONIC_JNB:
		this->getCompiler()->jnb(lbl);
		break;
	case ZYDIS_MNEMONIC_JNL:
		this->getCompiler()->jnl(lbl);
		break;
	case ZYDIS_MNEMONIC_JNLE:
		this->getCompiler()->jnle(lbl);
		break;
	case ZYDIS_MNEMONIC_JNO:
		this->getCompiler()->jno(lbl);
		break;
	case ZYDIS_MNEMONIC_JNP:
		this->getCompiler()->jnp(lbl);
		break;
	case ZYDIS_MNEMONIC_JNS:
		this->getCompiler()->jns(lbl);
		break;
	case ZYDIS_MNEMONIC_JNZ:
		this->getCompiler()->jnz(lbl);
		break;
	case ZYDIS_MNEMONIC_JO:
		this->getCompiler()->jo(lbl);
		break;
	case ZYDIS_MNEMONIC_JP:
		this->getCompiler()->jp(lbl);
		break;
	case ZYDIS_MNEMONIC_JS:
		this->getCompiler()->js(lbl);
		break;
	case ZYDIS_MNEMONIC_JZ:
		this->getCompiler()->jz(lbl);
		break;
	case ZYDIS_MNEMONIC_JMP:
		this->getCompiler()->jmp(lbl);
		break;
	case ZYDIS_MNEMONIC_CALL:
		this->getCompiler()->call(lbl);
		break;
	default:
		PERSES_THROW("Unknown JCC mnemonic passed into writeJcc.");
	}
}

MUT_TEMPLATE void MutationLightSchema<BitSize>::genXor(assembler::x86::Gp dst, assembler::x86::Gp val)
{
	// x ^ y = (x & ~y) | (~x & y)

	assembler::x86::Assembler* cc = this->getCompiler();
	assembler::x86::Gp stackReg;

	constexpr bool isx64 = BitSize == PERSES_64BIT;
	bool isDll = false;

	if (app())
	{
		isDll = app()->getImage().isDllOrSystemFile();
	}

	if constexpr (isx64)
	{
		stackReg = x86::regs::rsp;
	}
	else
	{
		stackReg = x86::regs::esp;
	}

	if (dst == val || dst == stackReg || val == stackReg)
	{
		cc->xor_(dst, val);
		return;
	}

	// This can be done a million times better
	cc->push(dst);

	if constexpr (isx64)
	{
		cc->not_(x86::qword_ptr(stackReg));
		cc->and_(x86::qword_ptr(stackReg), val);

		cc->push(val);
		cc->not_(val);
		cc->and_(dst, val);
		cc->pop(val);
		cc->or_(dst, x86::qword_ptr(stackReg));
		cc->add(stackReg, sizeof(u64));
	}
	else
	{
		cc->not_(x86::dword_ptr(stackReg));
		cc->and_(x86::dword_ptr(stackReg), val);

		cc->push(val);
		cc->not_(val);
		cc->and_(dst, val);
		cc->pop(val);
		cc->or_(dst, x86::dword_ptr(stackReg));
		cc->add(stackReg, dst.size());
	}
}

MUT_TEMPLATE void MutationLightSchema<BitSize>::genXorImm(assembler::x86::Gp dst, u32 val)
{
	// x ^ y = (x & ~y) | (~x & y)

	assembler::x86::Assembler* cc = this->getCompiler();
	assembler::x86::Gp stackReg;

	constexpr bool isx64 = BitSize == PERSES_64BIT;

	if constexpr (isx64)
		stackReg = x86::regs::rsp;
	else
		stackReg = x86::regs::esp;

	if constexpr (isx64)
	{
		cc->push(dst);
		cc->sub(stackReg, sizeof(u64));
		cc->mov(x86::qword_ptr(stackReg), val);

		// (~x & y)
		cc->not_(dst);
		cc->and_(dst, val);

		// restore dst.
		cc->xchg(x86::ptr(stackReg, sizeof(u64), dst.size()), dst);
		
		// (x & ~y)
		cc->not_(x86::dword_ptr(stackReg));
		cc->and_(dst, x86::ptr(stackReg));

		// OR op.
		cc->or_(dst, x86::ptr(stackReg, sizeof(u64)));

		cc->add(stackReg, sizeof(u64) << 1);
	}
	else
	{
		cc->push(val);
		cc->push(dst);
		cc->not_(x86::ptr(stackReg, 0, dst.size()));
		cc->and_(x86::ptr(stackReg, 0, dst.size()), val);
		cc->not_(x86::ptr(stackReg, dst.size(), 4));
		cc->and_(dst, x86::ptr(stackReg, dst.size(), 4));
		cc->or_(dst, x86::ptr(stackReg, 0, 4));
		cc->add(stackReg, 4 + dst.size());
	}
}

MUT_TEMPLATE void perses::MutationLightSchema<BitSize>::genAdd(assembler::x86::Gp dst, assembler::x86::Gp val)
{
	// (x + y) = (x - (~y)) - 1

	assembler::x86::Assembler* cc = this->getCompiler();

	assembler::x86::Gp stackReg;
	constexpr bool isx64 = BitSize == PERSES_64BIT;

	if constexpr (isx64)
		stackReg = x86::regs::rsp;
	else
		stackReg = x86::regs::esp;

	if (dst == stackReg || dst.size() != val.size())
	{
		cc->add(dst, val);
		return;
	}

	cc->push(val);
	cc->not_(val);
	cc->sub(dst, val);
	cc->pop(val);
	cc->sub(dst, 1);
}

MUT_TEMPLATE void MutationLightSchema<BitSize>::genAddImm(assembler::x86::Gp dst, u32 val)
{
	assembler::x86::Assembler* cc = this->getCompiler();
	assembler::x86::Gp stackReg;

	constexpr bool isx64 = BitSize == PERSES_64BIT;
	
	if constexpr (isx64)
		stackReg = x86::regs::rsp;
	else
		stackReg = x86::regs::esp;

	if (dst == stackReg || dst.size() != sizeof(u32))
	{
		cc->add(dst, val);
		return;
	}

	// x + y = not(not(x) - y)
	cc->not_(dst);
	cc->sub(dst, val);
	cc->not_(dst);
}

// Explicit templates.
template void perses::buildKnownRetGadgets<PERSES_32BIT>(X86BinaryApplication<PERSES_32BIT>* app);
template void perses::buildKnownRetGadgets<PERSES_64BIT>(X86BinaryApplication<PERSES_64BIT>* app);

template<int BitSize>
void perses::buildKnownRetGadgets(X86BinaryApplication<BitSize>* app)
{
	if (app && gs_retGadgets.empty())
	{
		if (app)
		{
			pepp::SectionHeader* xsec = nullptr;

			// Find first executable section
			for (int i = 0; i < app->getImage().getNumberOfSections(); ++i)
			{
				if (app->getImage().getSectionHdr(i).getCharacteristics() & pepp::SCN_MEM_EXECUTE)
				{
					xsec = &app->getImage().getSectionHdr(i);
					break;
				}
			}

			if (xsec)
			{
				// Find all locations in the executable section that have the RET opcode.
				auto offsets = app->getImage().findBinarySequence(xsec, "c3");

				// Translate all gadgets to raw addresses with the default base address
				for (auto& offset : offsets)
				{
					offset = app->getImage().getPEHdr().offsetToRva(offset);
					u64 gadget = offset + app->getBaseAddress();

					gs_retGadgets.push_back(gadget);

					// Build up to 0x1000 gadgets, you can remove this line to allow more
					if (gs_retGadgets.size() > 0x1000)
						break;
				}

				// NOTE: We build this list of RET's so we can jmp to them in the instruction stream instead of placing a `cc->ret()`.
				// This can potentially make a analyzer place a Label where there shouldn't be and break the corresponding disassembly.
			}
		}
	}

}

std::vector<u64> perses::getKnownRetGadgets()
{
	return gs_retGadgets;
}
