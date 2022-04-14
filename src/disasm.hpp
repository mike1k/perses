#pragma once

namespace perses
{

	struct instruction_t
	{
		bool isMnemonic(ZydisMnemonic mnem) const;
		bool isOperandType(size_t index, ZydisOperandType type) const;
		const ZydisDecodedOperand* getOperand(size_t index) const;
		size_t getFirstSegmentOffset(ZydisInstructionSegment type);

		uintptr_t address{ };
		ZydisDecodedInstruction decoded{ };
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{ };
		std::vector<uint8_t> raw{ };
	};

	class Disassembler
	{
	public:
		static Disassembler* instance();
		static void create(ZydisMachineMode mode);

		bool decode(void* buf, instruction_t* instr);
		bool decode(void* buf, ZydisDecodedInstruction* instr, ZydisDecodedOperand* op);
		u64 calcAbsolute(instruction_t* intr);
		u64 calcAbsolute(ZydisDecodedInstruction* instr, ZydisDecodedOperand* op, u64 address);
		ZydisRegister enclosingReg(ZydisRegister);
		bool getSegments(instruction_t* intr, ZydisInstructionSegments* segments);
		bool isJmp(instruction_t* instr);
		bool isBbTerminatorInstruction(instruction_t* instr);

		std::string format(address addr, ZydisDecodedInstruction* instr, ZydisDecodedOperand* op);

	private:
		ZydisDecoder	_decoder;
		ZydisFormatter	_formatter;
		ZydisMachineMode _mode;
	};


	class Routine : public std::vector<instruction_t>
	{
	public:
		Routine() = default;

		void buildFromCode(address buf);
		void printAssembly(uint32_t numInstructions = -1);

		void addFlag(int flag) { _flag |= flag;  }
		void stripFlag(int flag) { _flag &= ~flag; }
		int getFlag() const { return _flag; }
		size_t codeSize() const;

		uptr getAddress() const { return empty() ? 0 : at(0).address; }

	private:
		int _flag { };
	};
}