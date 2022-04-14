#include "perses.hpp"

using namespace perses;

static Disassembler s_disasm;

Disassembler* Disassembler::instance()
{
	return &s_disasm;
}

void Disassembler::create(ZydisMachineMode mode)
{
	// - Initialize formatter
	ZydisFormatterInit(&s_disasm._formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&s_disasm._formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

	s_disasm._mode = mode;

	if (mode == ZYDIS_MACHINE_MODE_LONG_64)
	{
		ZydisDecoderInit(&s_disasm._decoder, s_disasm._mode, ZYDIS_STACK_WIDTH_64);
		return;
	}
	
	if (mode == ZYDIS_MACHINE_MODE_LONG_COMPAT_32)
	{
		ZydisDecoderInit(&s_disasm._decoder, s_disasm._mode, ZYDIS_STACK_WIDTH_32);
		return;
	}

	PERSES_THROW("Unexpected machine mode passed into Disassembler::create()!");
}

bool Disassembler::decode(void* buf, instruction_t* instr)
{
	ZyanStatus status = ZydisDecoderDecodeFull(&_decoder, buf, 0xFFF, &instr->decoded, instr->operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

	if (ZYAN_SUCCESS(status))
	{
		instr->raw.resize(instr->decoded.length);
		memcpy(&instr->raw[0], buf, instr->decoded.length);
		return true;
	}

	return false;
}

bool Disassembler::decode(void* buf, ZydisDecodedInstruction* instr, ZydisDecodedOperand* op)
{
	return ZYAN_SUCCESS(
		ZydisDecoderDecodeFull(&_decoder, buf, 0xFFF, instr, op, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY));
}

u64 Disassembler::calcAbsolute(instruction_t* instr)
{
	u64 dst = 0ull;

	ZydisCalcAbsoluteAddress(&instr->decoded, &instr->operands[0], instr->address, &dst);

	return dst;
}

u64 perses::Disassembler::calcAbsolute(ZydisDecodedInstruction* instr, ZydisDecodedOperand* op, u64 address)
{
	u64 dst = 0ull;

	ZyanStatus status = ZydisCalcAbsoluteAddress(instr, op, address, &dst);

	return dst;
}

bool Disassembler::getSegments(instruction_t* intr, ZydisInstructionSegments* segments)
{
	return ZYAN_SUCCESS(
		ZydisGetInstructionSegments(&intr->decoded, segments));
}

bool Disassembler::isJmp(instruction_t* i)
{
	ZydisDecodedInstruction* instr = &i->decoded;

	switch (instr->mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
	return false;
}

bool Disassembler::isBbTerminatorInstruction(instruction_t* i)
{
	// Check if the instruction ends a basic block
	ZydisDecodedInstruction* instr = &i->decoded;

	switch (instr->mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_RET:
		return true;
	default:
		return false;
	}

	return false;
}

std::string Disassembler::format(address addr, ZydisDecodedInstruction* instr, ZydisDecodedOperand* op)
{
	char buf[0xFF]{};
	ZyanStatus status = 0;

	status = ZydisFormatterFormatInstruction(&_formatter, instr, op, instr->operand_count_visible, buf, sizeof(buf), addr.uintptr());

	if (!ZYAN_SUCCESS(status))
	{
		return fmt::format("Unexpected error when formatting address: 0x{:X}", addr.uintptr());
	}

	return buf;
}

void Routine::buildFromCode(address buf)
{
	return;
}

void Routine::printAssembly(uint32_t numInstructions)
{
	if (empty())
		return;

	logger()->info("** Printing routine: 0x{:X}", at(0).address);

	int count = 0;

	for (auto& instr : *this)
	{
		if (numInstructions != -1)
		{
			if (count++ >= numInstructions)
				break;
		}

		std::string fmt = Disassembler::instance()->format(instr.address, &instr.decoded, instr.operands);

		logger()->debug("** 0x{:X}\t\t|\t{}", instr.address, fmt);
	}
}

size_t perses::Routine::codeSize() const
{
	size_t sz {};
	for (auto& insn : *this)
		sz += insn.decoded.length;
	return sz;
}

bool instruction_t::isMnemonic(ZydisMnemonic mnem) const
{
	return decoded.mnemonic == mnem;
}

bool instruction_t::isOperandType(size_t index, ZydisOperandType type) const
{
	if (const ZydisDecodedOperand* op = getOperand(index))
	{
		return op->type == type;
	}
	return false;
}

const ZydisDecodedOperand* instruction_t::getOperand(size_t index) const
{
	if (index >= decoded.operand_count_visible)
		return nullptr;

	return &operands[index];
}

size_t instruction_t::getFirstSegmentOffset(ZydisInstructionSegment type)
{
	ZydisInstructionSegments segs { };
	Disassembler::instance()->getSegments(this, &segs);

	for (auto& seg : segs.segments)
	{
		if (seg.type == type)
			return seg.offset;
	}

	return 0ull;
}
