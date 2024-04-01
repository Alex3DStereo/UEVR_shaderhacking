#pragma once

#include <string>
#include <vector>
#include <list>

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

			unsigned opcode : 11;    // [10:00] D3D10_SB_OPCODE_DCL_RESOURCE
            unsigned dimension : 13; // [15:11] D3D10_SB_RESOURCE_DIMENSION
			unsigned length : 7;     // [30:24] Instruction length in DWORDs including the opcode token.
			unsigned extended : 1;   // [31]    0 normally. 1 if extended operand definition, meaning next DWORD contains extended operand description.
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

			unsigned comps_enum : 2;  // [01:00] D3D10_SB_OPERAND_NUM_COMPONENTS Number of components in data vector referred to by operand
			                          //         0 = D3D10_SB_OPERAND_0_COMPONENT, 1 = D3D10_SB_OPERAND_1_COMPONENT, 2 = D3D10_SB_OPERAND_4_COMPONENT
			unsigned mode : 2;        // [03:02] D3D10_SB_OPERAND_4_COMPONENT_SELECTION_MODE
			                          //         0 = D3D10_SB_OPERAND_4_COMPONENT_MASK_MODE, 1 = D3D10_SB_OPERAND_4_COMPONENT_SWIZZLE_MODE, 2 = D3D10_SB_OPERAND_4_COMPONENT_SELECT_1_MODE
			unsigned sel : 8;         // [11:04] Mask/Swizzle/Name
			unsigned file : 8;        // [19:12] D3D10_SB_OPERAND_TYPE
			                          //          0 = D3D10_SB_OPERAND_TYPE_TEMP = Temporary Register File
                                      //          1 = D3D10_SB_OPERAND_TYPE_INPUT = General Input Register File
                                      //          2 = D3D10_SB_OPERAND_TYPE_OUTPUT = General Output Register File
                                      //          3 = D3D10_SB_OPERAND_TYPE_INDEXABLE_TEMP = Temporary Register File (indexable)
                                      //          4 = D3D10_SB_OPERAND_TYPE_IMMEDIATE32 = 32bit/component immediate value(s)
                                      //              If for example, operand token bits [01:00]==D3D10_SB_OPERAND_4_COMPONENT, this means that this operand type results in 4 additional DWORDS present for the operand.
                                      //          5 = D3D10_SB_OPERAND_TYPE_IMMEDIATE64 = 64bit/comp.imm.val(s)HI:LO
                                      //          6 = D3D10_SB_OPERAND_TYPE_SAMPLER = Reference to sampler state
                                      //          7 = D3D10_SB_OPERAND_TYPE_RESOURCE = Reference to memory resource (e.g. texture)
                                      //          8 = D3D10_SB_OPERAND_TYPE_CONSTANT_BUFFER = Reference to constant buffer
                                      //          9 = D3D10_SB_OPERAND_TYPE_IMMEDIATE_CONSTANT_BUFFER = Reference to immediate constant buffer
                                      //         10 = D3D10_SB_OPERAND_TYPE_LABEL = Label
                                      //         11 = D3D10_SB_OPERAND_TYPE_INPUT_PRIMITIVEID = Input primitive ID
                                      //         12 = D3D10_SB_OPERAND_TYPE_OUTPUT_DEPTH = Output Depth
                                      //         13 = D3D10_SB_OPERAND_TYPE_NULL = Null register, used to discard results of operations
                                      //  Below Are operands new in DX 10.1
                                      //         14 = D3D10_SB_OPERAND_TYPE_RASTERIZER = DX10.1 Rasterizer register, used to denote the depth/stencil and render target resources
                                      //         15 = D3D10_SB_OPERAND_TYPE_OUTPUT_COVERAGE_MASK = DX10.1 PS output MSAA coverage mask (scalar)
                                      //  Below Are operands new in DX 11
                                      //         16 = D3D11_SB_OPERAND_TYPE_STREAM = Reference to GS stream output resource
                                      //         17 = D3D11_SB_OPERAND_TYPE_FUNCTION_BODY = Reference to a function definition
                                      //         18 = D3D11_SB_OPERAND_TYPE_FUNCTION_TABLE = Reference to a set of functions used by a class
                                      //         19 = D3D11_SB_OPERAND_TYPE_INTERFACE = Reference to an interface
                                      //         20 = D3D11_SB_OPERAND_TYPE_FUNCTION_INPUT = Reference to an input parameter to a function
                                      //         21 = D3D11_SB_OPERAND_TYPE_FUNCTION_OUTPUT = Reference to an output parameter to a function
                                      //         22 = D3D11_SB_OPERAND_TYPE_OUTPUT_CONTROL_POINT_ID = HS Control Point phase input saying which output control point ID this is 
									  //         23 = D3D11_SB_OPERAND_TYPE_INPUT_FORK_INSTANCE_ID = HS Fork Phase input instance ID
                                      //         24 = D3D11_SB_OPERAND_TYPE_INPUT_JOIN_INSTANCE_ID = HS Join Phase input instance ID
                                      //         25 = D3D11_SB_OPERAND_TYPE_INPUT_CONTROL_POINT = HS Fork+Join, DS phase input control points (array of them)
                                      //         26 = D3D11_SB_OPERAND_TYPE_OUTPUT_CONTROL_POINT = HS Fork+Join phase output control points (array of them)
                                      //         27 = D3D11_SB_OPERAND_TYPE_INPUT_PATCH_CONSTANT = DS+HSJoin Input Patch Constants (array of them)
                                      //         28 = D3D11_SB_OPERAND_TYPE_INPUT_DOMAIN_POINT = DS Input Domain point
                                      //         29 = D3D11_SB_OPERAND_TYPE_THIS_POINTER = Reference to an interface this pointer
                                      //         30 = D3D11_SB_OPERAND_TYPE_UNORDERED_ACCESS_VIEW = Reference to UAV u#
                                      //         31 = D3D11_SB_OPERAND_TYPE_THREAD_GROUP_SHARED_MEMORY = Reference to Thread Group Shared Memory g#
                                      //         32 = D3D11_SB_OPERAND_TYPE_INPUT_THREAD_ID = Compute Shader Thread ID
                                      //         33 = D3D11_SB_OPERAND_TYPE_INPUT_THREAD_GROUP_ID = Compute Shader Thread Group ID
                                      //         34 = D3D11_SB_OPERAND_TYPE_INPUT_THREAD_ID_IN_GROUP = Compute Shader Thread ID In Thread Group
                                      //         35 = D3D11_SB_OPERAND_TYPE_INPUT_COVERAGE_MASK = Pixel shader coverage mask input
                                      //         36 = D3D11_SB_OPERAND_TYPE_INPUT_THREAD_ID_IN_GROUP_FLATTENED = Compute Shader Thread ID In Group Flattened to a 1D value.
                                      //         37 = D3D11_SB_OPERAND_TYPE_INPUT_GS_INSTANCE_ID = Input GS instance ID
                                      //         38 = D3D11_SB_OPERAND_TYPE_OUTPUT_DEPTH_GREATER_EQUAL = Output Depth, forced to be greater than or equal than current depth
                                      //         39 = D3D11_SB_OPERAND_TYPE_OUTPUT_DEPTH_LESS_EQUAL = Output Depth, forced to be less than or equal to current depth
                                      //         40 = D3D11_SB_OPERAND_TYPE_CYCLE_COUNTER = Cycle counter
                                      //         41 = D3D11_SB_OPERAND_TYPE_OUTPUT_STENCIL_REF = DX11 PS output stencil reference (scalar)
                                      //         42 = D3D11_SB_OPERAND_TYPE_INNER_COVERAGE = DX11 PS input inner coverage (scalar)
			unsigned num_indices : 2; // [21:20] D3D10_SB_OPERAND_INDEX_DIMENSION: Number of dimensions in the register file
			unsigned index0_repr : 3; // [24:22] 1st D3D10_SB_OPERAND_INDEX_REPRESENTATION
			                          //         0 = D3D10_SB_OPERAND_INDEX_IMMEDIATE32 = Extra DWORD
                                      //         1 = D3D10_SB_OPERAND_INDEX_IMMEDIATE64 = Extra DWORDs (HI32:LO32)
                                      //         2 = D3D10_SB_OPERAND_INDEX_RELATIVE = Extra operand
                                      //         3 = D3D10_SB_OPERAND_INDEX_IMMEDIATE32_PLUS_RELATIVE = Extra DWORD followed by extra operand
                                      //         4 = D3D10_SB_OPERAND_INDEX_IMMEDIATE64_PLUS_RELATIVE = 2 Extra DWORDS (HI32:LO32) followed by extra operand
			unsigned index1_repr : 3; // [27:25] 2nd D3D10_SB_OPERAND_INDEX_REPRESENTATION
			unsigned index2_repr : 3; // [30:28] 3rd D3D10_SB_OPERAND_INDEX_REPRESENTATION
			unsigned extended : 1;    // [31]    0 normally. 1 if extended operand definition, meaning next DWORD contains extended operand description.
		};
		uint32_t op;
	};
};

std::vector<std::string> stringToLines(const char* start, size_t size);
int32_t disassembler(std::vector<uint8_t> *buffer, std::vector<uint8_t> *ret, const char *comment, int hexdump = 0);
std::vector<uint8_t> assembler(const std::string &sourceCode, std::vector<uint8_t> origBytecode, std::list<AssemblerParseError> &parse_errors);
std::vector<uint8_t> AssembleFluganWithSignatureParsing(const std::string &sourceCode, std::list<AssemblerParseError> &parse_errors);
std::vector<uint8_t> AssembleFluganWithOptionalSignatureParsing(const std::string &sourceCode, bool assemble_signatures, const std::vector<uint8_t> &orig_bytecode, std::list<AssemblerParseError> &parse_errors);
uint64_t hash_shader(const void* pShaderBytecode, uint64_t BytecodeLength);
std::string BinaryToAsmText(const void* pShaderBytecode, size_t BytecodeLength, int hexdump = 0);
std::vector<uint8_t> ReplaceASMShader(const uint64_t hash, const char* pShaderType, const void* pShaderBytecode, uint64_t pBytecodeLength);

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
