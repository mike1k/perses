#pragma once

namespace perses
{
	template<int BitSize>
	class MutationLightSchema : public ProtectionSchema
	{
	public:
		perses::assembler::CodeBuffer applyTransforms(Routine* rtn) override;
		bool handlePush(instruction_t* insn);
		bool handleMov(instruction_t* insn);
		bool handleXor(instruction_t* insn);
		bool handleAdd(instruction_t* insn);
		bool handleRelInstruction(instruction_t* insn);
		X86BinaryApplication<BitSize>* app();
	protected:
		void makeRelocation(int offset, bool relative = false, u64 absolute = 0ull);
		u32 toRva(uptr address);
		void fetchPeb(assembler::x86::Gp dst);
		bool recoverJumpTable(instruction_t* insn);
		void writeJcc(ZydisDecodedInstruction* instr, assembler::Label& lbl);
		void genXor(assembler::x86::Gp dst, assembler::x86::Gp val);
		void genXorImm(assembler::x86::Gp dst, u32 val);
		void genAdd(assembler::x86::Gp dst, assembler::x86::Gp val);
		void genAddImm(assembler::x86::Gp dst, u32 val);
	private:
		struct RelocGenEntry
		{
			u16 ioffset;
			u16 roffset;
			u16 length;
			u64 absolute;
		};

		// Upper half of each entry stores the assosciated instruction's length
		// Lower half will store the offet the relocation should happen.
		std::vector<RelocGenEntry> _relocEntryList;
		instruction_t* _currentInstruction;
		uptr _rtnBegin, _rtnEnd;
		std::vector<JumpTableEntry> _jumpTables;
		u32 _streamOffset;
		Routine *_rtn;
	};

	template<int BitSize>
	void buildKnownRetGadgets(X86BinaryApplication<BitSize>* app);
	std::vector<u64> getKnownRetGadgets();
}