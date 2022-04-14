#pragma once

namespace perses
{
	template<int>
	class X86BinaryApplication;

	class ProtectionSchema
	{
	public:
		virtual ~ProtectionSchema() = default;
		virtual perses::assembler::CodeBuffer applyTransforms(Routine* rtn) = 0;

		template<typename SchemaType>
		[[nodiscard]] static SharedProtectionSchema create() {
			return std::shared_ptr<SchemaType>(new SchemaType());
		}

		void setApplication(void* app) { _app = app; }
		void* getApplication() { return _app; }

		assembler::x86::Assembler* getCompiler() { return &_compiler; }
	
	protected:
		// Intellisense failing hard here.
		void*						_app;
		assembler::CodeHolder		_code;
		assembler::x86::Assembler	_compiler;
		std::vector<RelocationEntry> _relocs;
	};
}

#include "MutationLight.hpp"