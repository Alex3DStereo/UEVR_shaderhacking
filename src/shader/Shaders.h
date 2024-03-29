#pragma once

#include <string>
#include <vector>

// VS2013 BUG WORKAROUND: Make sure this class has a unique type name!
class AssemblerParseError: public std::exception 
{
public:
	std::string context, desc, msg;
	int line_no;

	AssemblerParseError(std::string context, std::string desc) :
		context(context),
		desc(desc),
		line_no(0)
	{
		update_msg();
	}

	void update_msg()
	{
		msg = "Assembly parse error";
		if (line_no > 0)
			msg += std::string(" on line ") + std::to_string(line_no);
		msg += ", " + desc + ":\n\"" + context + "\"";
	}

	const char* what() const
	{
		return msg.c_str();
	}
};

struct shader_ins
{
	union {
		struct {
			// XXX Beware that bitfield packing is not defined in
			// the C/C++ standards and this is relying on compiler
			// specific packing. This approach is not recommended.

			unsigned opcode : 11;
			unsigned _11_23 : 13;
			unsigned length : 7;
			unsigned extended : 1;
		};
		uint32_t op;
	};
};
struct token_operand
{
	union {
		struct {
			// XXX Beware that bitfield packing is not defined in
			// the C/C++ standards and this is relying on compiler
			// specific packing. This approach is not recommended.

			unsigned comps_enum : 2; /* sm4_operands_comps */
			unsigned mode : 2; /* sm4_operand_mode */
			unsigned sel : 8;
			unsigned file : 8; /* SM_FILE */
			unsigned num_indices : 2;
			unsigned index0_repr : 3; /* sm4_operand_index_repr */
			unsigned index1_repr : 3; /* sm4_operand_index_repr */
			unsigned index2_repr : 3; /* sm4_operand_index_repr */
			unsigned extended : 1;
		};
		uint32_t op;
	};
};

std::vector<std::string> stringToLines(const char* start, size_t size);
int32_t disassembler(std::vector<uint8_t> *buffer, std::vector<uint8_t> *ret, const char *comment, int hexdump = 0);
std::vector<uint8_t> assembler(std::vector<char> *asmFile, std::vector<uint8_t> origBytecode, std::vector<AssemblerParseError> *parse_errors = NULL);
void writeLUT();
int32_t AssembleFluganWithSignatureParsing(std::vector<char> *assembly, std::vector<uint8_t> *result_bytecode, std::vector<AssemblerParseError> *parse_errors = NULL);
std::vector<uint8_t> AssembleFluganWithOptionalSignatureParsing(std::vector<char> *assembly, bool assemble_signatures, std::vector<uint8_t> *orig_bytecode, std::vector<AssemblerParseError> *parse_errors = NULL);
uint64_t hash_shader(const void* pShaderBytecode, uint64_t BytecodeLength);
std::string BinaryToAsmText(const void* pShaderBytecode, size_t BytecodeLength, int hexdump = 0);
char *ReplaceASMShader(const uint64_t hash, const char* pShaderType, const void* pShaderBytecode, uint64_t pBytecodeLength, uint64_t& pCodeSize);

#pragma pack(push, 1)

struct dxbc_header {
	char signature[4]; // DXCB
	uint32_t hash[4]; // Not quite MD5
	uint32_t one; // File version? Always 1
	uint32_t size;
	uint32_t num_sections;
};

struct section_header {
	char signature[4];
	uint32_t size;
};

struct sgn_header {
	uint32_t num_entries;
	uint32_t unknown; // Always 0x00000008? Probably the offset to the sgn_entry array
};

struct sgn_entry_common {
	uint32_t semantic_index;
	uint32_t system_value;
	uint32_t format;
	uint32_t reg;
	uint8_t  mask;
	uint8_t  used;
	uint16_t zero; // 0x0000
};

struct sgn_entry_serialiased { // Base version - 24 bytes
	uint32_t name_offset; // Relative to the start of sgn_header
	struct sgn_entry_common common;
	// Followed by an unpadded array of null-terminated names
	// Whole structure padded to a multiple of 4 bytes with 0xAB
};

struct sg5_entry_serialiased { // Version "5" (only exists for geometry shader outputs) - 28 bytes
	uint32_t stream;
	struct sgn_entry_serialiased sgn;
};

struct sg1_entry_serialiased { // "Version "1" (most recent - I assume that's 5.1?) - 32 bytes
	struct sg5_entry_serialiased sg5;
	uint32_t min_precision;
};

#pragma pack(pop)

struct sgn_entry_unserialised {
	uint32_t stream;
	std::string name;
	uint32_t name_offset; // Relative to start of the name list
	struct sgn_entry_common common;
	uint32_t min_precision;
};
