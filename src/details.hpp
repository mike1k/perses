#pragma once

// - MACROs for specific toggles
#define PERSES_VERBOSE
#define PERSES_DEBUGGABLE

#ifdef PERSES_DEBUGGABLE

#define PERSES_THROW(msg) throw msg
#define PERSES_THROWIFN(cnd, msg) if (!cnd) PERSES_THROW(msg)
#define PERSES_THROWIF(cnd, msg) if (cnd) PERSES_THROW(msg)

#else

#define PERSES_THROW(msg)
#define PERSES_THROWIFN(cnd, msg)
#define PERSES_THROWIF(cnd, msg)

#endif

#define PERSES_32BIT 32
#define PERSES_64BIT 64


#define PERSES_MARKER_MUTATION 0
#define PERSES_MARKER_VIRTUALIZATION 1

// #define PERSES_BITSTOBYTES(bits) (((bits) + 7) >> 3)
// #define PERSES_BYTESTOBITS(bits) (bits << 3)

constexpr auto PERSES_BITSTOBYTES(size_t bits) noexcept {
	return (((bits)+7) >> 3);
}

constexpr auto PERSES_BYTESTOBITS(size_t bytes) noexcept {
	return (bytes << 3);
}

namespace perses
{
	class ProtectionSchema;

	namespace pe = pepp;
	namespace assembler = asmjit;

	using address = pe::Address< >;
	using u8 = uint8_t;
	using u16 = uint16_t;
	using u32 = uint32_t;
	using u64 = uint64_t;
	using uptr = uintptr_t;
	using SharedProtectionSchema = std::shared_ptr<ProtectionSchema>;

	struct RelocationEntry
	{
		pepp::RelocationType type;
		u32 offset;
		// Only used on x64 for RIP relative instructions.
		u32 base;
		u32 length;
		u64 absolute;
		u64 stream = 0ull;
	};

	struct JumpTableEntry
	{
		u32 rva;
		u64 address;
		u32 newOffset;
		assembler::Label label;
	};

	// - These are what get scanned in .text sections by the engine
	// - These two are the begin/end markers respectively.
	// - LIMITATIONS:
	//  * These markers MUST be 5 bytes in length!
	inline std::tuple<int, std::string, u64> MarkerTags[] =
	{
		{PERSES_MARKER_MUTATION, "CC CC 90 90 FA", 0xCCCC9090FBull}
	};
}

#define PERSES_MUTATE_FULL 0xf001c0de
#define PERSES_MARKER_SIZE 0x5