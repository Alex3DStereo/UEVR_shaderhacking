#include "Shaders.h"
#include <spdlog/spdlog.h>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include "Framework.hpp"

#define SFI_RAW_STRUCT_BUF (1LL<<1)
#define SFI_MIN_PRECISION  (1LL<<4)

using namespace std;

// Force the use of SHader EXtended bytecode when certain features are in use,
// such as partial or double precision. This is likely incomplete.
#define SFI_FORCE_SHEX (SFI_RAW_STRUCT_BUF | SFI_MIN_PRECISION)

// VS2013 BUG WORKAROUND: Make sure this class has a unique type name!
class AsmSignatureParseError : public std::exception {} parseError;

static string next_line(const std::string &shader, size_t &pos)
{
	size_t start_pos = pos;
	size_t end_pos;

	// Skip preceeding whitespace:
	start_pos = shader.find_first_not_of(" \t\r", start_pos);

	// Blank line at end of file:
	if (start_pos == std::string::npos) {
		pos = std::string::npos;
		return "";
	}

	// Find newline, update parent pointer:
	pos = shader.find('\n', start_pos);

	// Skip trailing whitespace (will pad it later during parsing, but
	// can't rely on whitespace here so still strip it):
	end_pos = shader.find_last_not_of(" \t\n\r", pos) + 1;

	if (pos != std::string::npos)
		++pos;

	return shader.substr(start_pos, end_pos - start_pos);
}

struct format_type {
	uint32_t format;
	uint32_t min_precision;
	string name;
};

static struct format_type format_names[] = {
	{0, 0, "unknown" },
	{1, 0, "uint"    },
	{1, 5, "min16u"  }, // min16uint
	{2, 0, "int"     },
	{2, 4, "min16i"  }, // min16int *AND* min12int as of d3dcompiler47.dll
	{3, 0, "float"   },
	{3, 1, "min16f"  }, // min16float
	{3, 2, "min2_8f" }, // min10float
};

static void parse_format(char *format, uint32_t *format_number, uint32_t *min_precision)
{
	uint32_t i;

	for (i = 0; i < ARRAYSIZE(format_names); i++) {
		if (!strcmp(format, format_names[i].name.c_str())) {
			*format_number = format_names[i].format;
			*min_precision = format_names[i].min_precision;
			return;
		}
	}

	throw parseError;
}

struct svt {
	uint32_t val;
	string short_name;
};

static struct svt system_value_abbreviations[] = {
	{  0, "NONE",      }, // TEXCOORDs, input position to VS
	{  0, "TARGET",    }, // SV_Target

	{  1, "POS",       }, // SV_Position
	{  2, "CLIPDST",   }, // SV_ClipDistance
	{  3, "CULLDST",   }, // SV_CullDistance
	{  4, "RTINDEX",   }, // SV_RenderTargetArrayIndex
	{  5, "VPINDEX",   }, // SV_ViewportArrayIndex
	{  6, "VERTID",    }, // SV_VertexID
	{  7, "PRIMID",    }, // SV_PrimitiveID, register = "   primID"
	{  8, "INSTID",    }, // SV_InstanceID
	{  9, "FFACE",     }, // SV_IsFrontFace
	{ 10, "SAMPLE",    }, // SV_SampleIndex

	// Tesselation domain/hull shaders. XXX: These numbers don't match up
	// with BinaryDecompiler, but I got them myself, so I am 100% certain
	// they are right, but perhaps I am missing something (Update - now
	// pretty sure the values in BinaryDecompiler are those used in the
	// bytecode, whereas these values are used in the signatures):
	{ 11, "QUADEDGE",  }, // SV_TessFactor with [domain("quad")]
	{ 12, "QUADINT",   }, // SV_InsideTessFactor with [domain("quad")]
	{ 13, "TRIEDGE",   }, // SV_TessFactor with [domain("tri")]
	{ 14, "TRIINT",    }, // SV_InsideTessFactor with [domain("tri")]
	{ 15, "LINEDET",   },
	{ 16, "LINEDEN",   },

	// System values using SPRs (special purpose registers). These only
	// ever seem to show up in the output signature - any used as inputs is
	// not in the input signature, and uses a 'v' prefix instead of 'o'.
	// Mask = "N/A" (0x1)
	// Register = "oSomething" (0xffffffff)
	// Used = "YES" (0xe) / "NO" (0x0)
	{  0, "DEPTH"      }, // SV_Depth, oDepth
	{  0, "COVERAGE",  }, // SV_Coverage, oMask
	{  0, "DEPTHGE"    }, // SV_DepthGreaterEqual, oDepthGE
	{  0, "DEPTHLE"    }, // SV_DepthLessEqual, oDepthLE

	// Only available in DX12 / shader model 5.1 / d3dcompiler47.dll:
	{  0, "STENCILREF" }, // SV_StencilRef, oStencilRef
	{  0, "INNERCOV"   }, // SV_InnerCoverage, not sure what register is listed as - "special"?

	// Some other semantics which don't appear here (e.g. SV_GSInstanceID,
	// any of the compute shader thread IDs) are not present in these
	// sections.
};

static uint32_t parse_system_value(char *sv)
{
	uint32_t i;

	for (i = 0; i < ARRAYSIZE(system_value_abbreviations); i++) {
		if (!strcmp(sv, system_value_abbreviations[i].short_name.c_str()))
			return system_value_abbreviations[i].val;
	}

	throw parseError;
}

static uint8_t parse_mask(char mask[8], bool invert)
{
	uint8_t xor_val = (invert ? 0xf : 0);
	uint8_t ret = 0;
	int i;

	// This allows for more flexible processing rather than just limiting
	// it to what the disassembler generates

	for (i = 0; i < 8 && mask[i]; i++) {
		switch (mask[i]) {
			case 'x':
				ret |= 0x1;
				break;
			case 'y':
				ret |= 0x2;
				break;
			case 'z':
				ret |= 0x4;
				break;
			case 'w':
				ret |= 0x8;
				break;
			case ' ':
				break;
			// Special matches for semantics using special purpose registers:
			case 'Y': // YES
				return 0x1 ^ xor_val;
			case 'N': // NO or N/A - wait for next character
				break;
			case 'O': // NO
				return 0x0 ^ xor_val;
			case '/': // N/A
				return 0x1 ^ xor_val;
			default:
				throw parseError;
		}
	}
	return ret ^ xor_val;
}

static uint32_t pad(uint32_t size, uint32_t multiple)
{
	return (multiple - size % multiple) % multiple;
}

static std::vector<uint8_t> serialise_signature_section(const char *section24, const char *section28, const char *section32, int entry_size, const std::list<sgn_entry_unserialised> &entries, uint32_t name_len)
{
	uint32_t section_size, padding, alloc_size, name_off;
	char *name_ptr = NULL;
	void *padding_ptr = NULL;
	section_header *sectionHeader{};
	sgn_header *sgn_header = NULL;
	sgn_entry_serialiased *entryn = NULL;
	sg5_entry_serialiased *entry5 = NULL;
	sg1_entry_serialiased *entry1 = NULL;

	// Geometry shader 5 never uses OSGN, bump to OSG5:
	if (entry_size == 24 && section24 == NULL)
		entry_size = 28;

	// Only OSG5 exists in version 5, so bump ISG & PSG to version 5.1:
	if (entry_size == 28 && section28 == NULL)
		entry_size = 32;

	// Calculate various offsets and sizes:
	name_off = (uint32_t)(sizeof(sgn_header) + (entry_size * entries.size()));
	section_size = name_off + name_len;
	padding = pad(section_size, 4);
	std::vector<uint8_t> section(section_size + sizeof(section_header) + padding);

	// LogDebug("name_off: %u, name_len: %u, section_size: %u, padding: %u, alloc_size: %u\n",	name_off, name_len, section_size, padding, alloc_size);

	// Pointers to useful data structures and offsets in the buffer:
	sectionHeader = (section_header*)section.data();
	sgn_header = (struct sgn_header*)((char*)sectionHeader + sizeof(section_header));
	padding_ptr = (void*)((char*)sgn_header + section_size);
	// Only one of these will be used as the base address depending on the
	// structure version, but pointers to the older versions will also be
	// updated during the iteration:
	entryn = (struct sgn_entry_serialiased*)((char*)sgn_header + sizeof(struct sgn_header));
	entry5 = (struct sg5_entry_serialiased*)entryn;
	entry1 = (struct sg1_entry_serialiased*)entryn;

	// LogDebug("section: 0x%p, section_header: 0x%p, sgn_header: 0x%p, padding_ptr: 0x%p, entry: 0x%p\n", section, (char*)section_header, sgn_header, padding_ptr, entryn);

	switch (entry_size) {
		case 24:
			memcpy(&sectionHeader->signature, section24, 4);
			break;
		case 28:
			memcpy(&sectionHeader->signature, section28, 4);
			break;
		case 32:
			memcpy(&sectionHeader->signature, section32, 4);
			break;
		default:
			throw parseError;
	}
	sectionHeader->size = section_size + padding;

	sgn_header->num_entries = (uint32_t)entries.size();
	sgn_header->unknown = sizeof(struct sgn_header); // Not confirmed, but seems likely. Always 8

	// Fill out entries:
	for (auto &unserialised : entries) {
		switch (entry_size) {
			case 32:
				entry1->min_precision = unserialised.min_precision;
				entry5 = &entry1->sg5;
				entry1++;
				// Fall through
			case 28:
				entry5->stream = unserialised.stream;
				entryn = &entry5->sgn;
				entry5++;
				// Fall through
			case 24:
				entryn->name_offset = name_off + unserialised.name_offset;
				name_ptr = (char*)sgn_header + entryn->name_offset;
				memcpy(name_ptr, unserialised.name.c_str(), unserialised.name.size() + 1);
				memcpy(&entryn->common, &unserialised.common, sizeof(struct sgn_entry_common));
				entryn++;
		}
	}

	memset(padding_ptr, 0xab, padding);

	return section;
}

static std::vector<uint8_t> parse_signature_section(const char *section24, const char *section28, const char *section32, const std::string &shader, size_t &pos, bool invert_used, uint64_t sfi)
{
	string line;
	size_t old_pos = pos;
	int numRead;
	uint32_t name_off = 0;
	int entry_size = 24; // We use the size, because in MS's usual wisdom version 1 is higher than version 5 :facepalm:
	char semantic_name[64]; // Semantic names are limited to 63 characters in fxc
	char semantic_name2[64];
	char system_value[16]; // More than long enough for even "STENCILREF"
	char reg[16]; // More than long enough for even "oStencilRef"
	char mask[8], used[8]; // We read 7 characters - check the reason below
	char format[16]; // Long enough for even "unknown"
	std::list<sgn_entry_unserialised> entries;
	sgn_entry_unserialised entry;

	// If minimum precision formats are in use we bump the section versions:
	if (sfi & SFI_MIN_PRECISION)
		entry_size = max(entry_size, 32);

	while (pos != std::string::npos) {
		line = next_line(shader, pos);

		// LogDebug("%s\n", line.c_str());

		if (line == "//"
		 || line == "// Name                 Index   Mask Register SysValue  Format   Used"
		 || line == "// -------------------- ----- ------ -------- -------- ------- ------") {
			continue;
		}

		if (line == "// no Input"
		 || line == "// no Output"
		 || line == "// no Patch Constant") {
			// Empty section, but we still need to manufacture it
			break;
		}

		// Mask and Used can be empty or have spaces in them, so using
		// %s would not match them correctly. Instead, match exactly 7
		// characters, which will include some preceeding whitespace
		// that parse_mask will skip over. But, since we may have
		// stripped trailing whitespace, explicitly pad the string to
		// make sure Usage has 7 characters to match, and make sure
		// they are initialised to ' ':
		memset(mask, ' ', 8);
		memset(used, ' ', 8);

		numRead = sscanf_s((line + "       ").c_str(),
				"// %s %d%7c %s %s %s%7c",
				semantic_name, (unsigned)ARRAYSIZE(semantic_name),
				&entry.common.semantic_index,
				mask, (unsigned)ARRAYSIZE(mask),
				&reg, (unsigned)ARRAYSIZE(reg),
				system_value, (unsigned)ARRAYSIZE(system_value),
				format, (unsigned)ARRAYSIZE(format),
				used, (unsigned)ARRAYSIZE(used));

		if (numRead != 7) {
			// I really would love to throw parseError here to
			// catch typos, but since this is in a comment I can't
			// be certain that this is part of the signature
			// declaration, so I have to assume this is the end of
			// the section :(
			break;
		}

		// Try parsing the semantic name with streams, and bump the
		// section version if sucessful:
		numRead = sscanf_s(semantic_name, "m%u:%s",
				&entry.stream,
				semantic_name2, (unsigned)ARRAYSIZE(semantic_name2));
		if (numRead == 2) {
			entry_size = max(entry_size, 28);
			entry.name = semantic_name2;
		} else {
			entry.stream = 0;
			entry.name = semantic_name;
		}

		// Parse the format. If it is one of the minimum precision
		// formats, bump the section version (this is probably
		// redundant now that we bump the version based on SFI):
		parse_format(format, &entry.common.format, &entry.min_precision);
		if (entry.min_precision)
			entry_size = max(entry_size, 32);

		// Try parsing register as a decimal number. If it is not, it
		// is a special purpose register, in which case we store -1:
		if (numRead = sscanf_s(reg, "%d", &entry.common.reg) == 0)
			entry.common.reg = 0xffffffff;

		entry.common.system_value = parse_system_value(system_value);
		entry.common.mask = parse_mask(mask, false);
		entry.common.used = parse_mask(used, invert_used);
		entry.common.zero = 0;

		// Check if a previous entry used the same semantic name
        auto i = entries.begin();
        while (i != entries.end()) {
            if (i->name == entry.name) {
                entry.name_offset = i->name_offset;
                break;
			}
            ++i;
		}
        if (i == entries.end()) {
            entry.name_offset = name_off;
            name_off += (uint32_t)entry.name.size() + 1;
        }

		//LogDebug("Stream: %i, Name: %s, Index: %i, Mask: 0x%x, Register: %i, SysValue: %i, Format: %i, Used: 0x%x, Precision: %i\n",
		//		entry.stream, entry.name.c_str(),
		//		entry.common.semantic_index, entry.common.mask,
		//		entry.common.reg, entry.common.system_value,
		//		entry.common.format, entry.common.used,
		//		entry.min_precision);

		entries.emplace_back(std::move(entry));
		old_pos = pos;
	}
	// Wind the pos pointer back to the start of the line in case it is
	// another section that the caller will need to parse:
	pos = old_pos;

	return serialise_signature_section(section24, section28, section32, entry_size, entries, name_off);
}

static std::vector<uint8_t> serialise_subshader_feature_info_section(uint64_t flags)
{
    std::vector<uint8_t> section;
	const uint32_t section_size = 8;
	const uint32_t alloc_size = sizeof(section_header) + section_size;
	uint64_t *flags_ptr = NULL;

	if (!flags) {
        return section;
	}

	// Allocate entire section, including room for section header and padding:
    section.resize(alloc_size);

	// Pointers to useful data structures and offsets in the buffer:
    section_header* sectionHeader = (section_header*)section.data();
	memcpy(sectionHeader->signature, "SFI0", 4);
	sectionHeader->size = section_size;

	flags_ptr = (uint64_t *)((char*)sectionHeader + sizeof(section_header));
	*flags_ptr = flags;

	return section;
}

struct gf_sfi {
	uint64_t sfi;
	int len;
	string gf;
};

static struct gf_sfi global_flag_sfi_map[] = {
	{ 1LL<<0, 29, "enableDoublePrecisionFloatOps" },
	{ SFI_RAW_STRUCT_BUF, 29, "enableRawAndStructuredBuffers" }, // Confirmed
	{ SFI_MIN_PRECISION, 22, "enableMinimumPrecision" },
	{ 1LL<<5, 26, "enable11_1DoubleExtensions" },
	{ 1LL<<6, 26, "enable11_1ShaderExtensions" },

	// Does not map to SFI:
	// "refactoringAllowed"
	// "forceEarlyDepthStencil"
	// "skipOptimization"
	// "allResourcesBound"
};

static string subshader_feature_comments[] = {
	// d3dcompiler_46:
	"Double-precision floating point",
	//"Early depth-stencil", // d3dcompiler46/47 produces this output for [force, but it does *NOT* map to an SFI flag
	"Raw and Structured buffers", // DirectXShaderCompiler lists this in this position instead, which matches the globalFlag mapping
	"UAVs at every shader stage",
	"64 UAV slots",
	"Minimum-precision data types",
	"Double-precision extensions for 11.1",
	"Shader extensions for 11.1",
	"Comparison filtering for feature level 9",
	// d3dcompiler_47:
	"Tiled resources",
	"PS Output Stencil Ref",
	"PS Inner Coverage",
	"Typed UAV Load Additional Formats",
	"Raster Ordered UAVs",
	"SV_RenderTargetArrayIndex or SV_ViewportArrayIndex from any shader feeding rasterizer",
	// DX12 DirectXShaderCompiler (tools/clang/tools/dxcompiler/dxcdisassembler.cpp)
	"Wave level operations",
	"64-Bit integer",
	"View Instancing",
	"Barycentrics",
	"Use native low precision",
	"Shading Rate"
};

// Parses the globalFlags in the bytecode to derive Subshader Feature Info.
// This is incomplete, as some of the SFI flags are not in globalFlags, but
// must be found from the "shader requires" comment block instead.
uint64_t parse_global_flags_to_sfi(const std::string &shader)
{
	uint64_t sfi = 0LL;
	string line;
	size_t pos = 0, gf_pos = 16;
	int i;

	while (pos != std::string::npos) {
		line = next_line(shader, pos);
        if (line.starts_with("dcl_globalFlags ")) {
			// LogDebug("%s\n", line.c_str());
			while (gf_pos != string::npos) {
				for (i = 0; i < ARRAYSIZE(global_flag_sfi_map); i++) {
					if (!line.compare(gf_pos, global_flag_sfi_map[i].len, global_flag_sfi_map[i].gf)) {
						// LogDebug("Mapped %s to Subshader Feature 0x%llx\n",
						//		global_flag_sfi_map[i].gf, global_flag_sfi_map[i].sfi);
						sfi |= global_flag_sfi_map[i].sfi;
						gf_pos += global_flag_sfi_map[i].len;
						break;
					}
				}
				gf_pos = line.find_first_of(" |", gf_pos);
				gf_pos = line.find_first_not_of(" |", gf_pos);
			}
			return sfi;
		}
	}
	return 0;
}

// Parses the SFI comment block. This is not complete, as some of the flags
// come from globalFlags instead of / as well as this.
static uint64_t parse_subshader_feature_info_comment(const std::string &shader, size_t &pos, uint64_t flags)
{
	string line;
	size_t old_pos = pos;
	uint32_t i;

	while (pos != std::string::npos) {
		line = next_line(shader, pos);

		// LogDebug("%s\n", line.c_str());

		for (i = 0; i < ARRAYSIZE(subshader_feature_comments); i++) {
			if (!strcmp(line.c_str() + 9, subshader_feature_comments[i].c_str())) {
				// LogDebug("Matched Subshader Feature Comment 0x%llx\n", 1LL << i);
				flags |= 1LL << i;
				break;
			}
		}
		if (i == ARRAYSIZE(subshader_feature_comments))
			break;
	}

	// Wind the pos pointer back to the start of the line in case it is
	// another section that the caller will need to parse:
	pos = old_pos;

	return flags;
}

static std::vector<uint8_t> manufacture_empty_section(const char* section_name) 
{
    std::vector<uint8_t> section(8);
	spdlog::info("Manufacturing placeholder {} section...", section_name);
	memcpy(section.data(), section_name, 4);
	return section;
}

static bool is_hull_shader(const std::string &shader, size_t start_pos) {
	size_t pos = start_pos;

	while (pos != std::string::npos) {
		string line = next_line(shader, pos);
		if (line.starts_with("hs_4_"))
			return true;
		if (line.starts_with("hs_5_"))
			return true;
		if (line.compare(1, 4, "s_4_") == 0)
			return false;
		if (line.compare(1, 4, "s_5_") == 0)
			return false;
	}

	return false;
}

static bool is_geometry_shader_5(const string &shader, size_t start_pos) {
	size_t pos = start_pos;

	while (pos != std::string::npos) {
		string line = next_line(shader, pos);
		if (line.starts_with("gs_5_"))
			return true;
		if (line.compare(1, 4, "s_4_") == 0)
			return false;
		if (line.compare(1, 4, "s_5_") == 0)
			return false;
	}

	return false;
}

static std::vector<uint8_t> parse_section(const std::string &line, const std::string &shader, size_t &pos, uint64_t &sfi, bool force_shex, bool &done)
{
    if (line.compare(1, 4, "s_4_") == 0) {
        done = true;
        if ((sfi & SFI_FORCE_SHEX) || force_shex) {
            return manufacture_empty_section("SHEX");
        }
		return manufacture_empty_section("SHDR");
	}
	if (line.compare(1, 4, "s_5_") == 0) {
        done = true;
		return manufacture_empty_section("SHEX");
	}

	done = false;
	if (line.starts_with("// Patch Constant signature:")) {
        spdlog::info("Parsing Patch Constant Signature section...");
		return parse_signature_section("PCSG", NULL, "PSG1", shader, pos, is_hull_shader(shader, pos), sfi);
	} 
	if (line.starts_with("// Input signature:")) {
        spdlog::info("Parsing Input Signature section...");
		return parse_signature_section("ISGN", NULL, "ISG1", shader, pos, false, sfi);
	} 
	if (line.starts_with("// Output signature:")) {
        spdlog::info("Parsing Output Signature section...");
		const char *section24 = "OSGN";
        if (is_geometry_shader_5(shader, pos)) {
            section24 = NULL;
        }
		return parse_signature_section(section24, "OSG5", "OSG1", shader, pos, true, sfi);
	}
	if (line.starts_with("// Note: shader requires additional functionality:")) {
        spdlog::info("Parsing Subshader Feature Info section...");
		sfi = parse_subshader_feature_info_comment(shader, pos, sfi);
	} else if (line.starts_with("// Note: SHADER WILL ONLY WORK WITH THE DEBUG SDK LAYER ENABLED.")) {
		force_shex = true;
	}
    return std::vector<uint8_t>{};
}

static std::vector<uint8_t> serialise_shader_binary(const std::list<std::vector<uint8_t>> &sections)
{
	struct dxbc_header *header = NULL;
	uint32_t *section_offset_ptr = NULL;
	void *section_ptr = NULL;

	// Calculate final size of shader binary:
    size_t allSectionsSize{};
    for (auto& section : sections)
        allSectionsSize += section.size();
    std::vector<uint8_t> bytecode(sizeof(dxbc_header) + 4 * sections.size() + allSectionsSize);

	// Get some useful pointers into the buffer:
	header = (struct dxbc_header*)bytecode.data();
	section_offset_ptr = (uint32_t*)((char*)header + sizeof(struct dxbc_header));
	section_ptr = (void*)(section_offset_ptr + sections.size());

	memcpy(header->signature, "DXBC", 4);
	memset(header->hash, 0, sizeof(header->hash)); // Will be filled in by assembler
	header->one = 1;
	header->size = bytecode.size();
	header->num_sections = (uint32_t)sections.size();

	for (auto &section : sections) {
		memcpy(section_ptr, section.data(), section.size());
		*section_offset_ptr = (uint32_t)((char*)section_ptr - (char*)header);
		section_offset_ptr++;
		section_ptr = (char*)section_ptr + section.size();
	}
    return bytecode;
}

static vector<uint8_t> manufacture_shader_binary(const std::string& sourceCode) 
{
	std::string line;
	size_t pos = 0;
	bool done = false;
	std::list<std::vector<uint8_t>> sections;
	bool force_shex = false;

	uint64_t sfi = parse_global_flags_to_sfi(sourceCode);

	while (!done && pos != std::string::npos) {
		line = next_line(sourceCode, pos);
		//LogInfo("%s\n", line.c_str());

		std::vector<uint8_t> section = parse_section(line, sourceCode, pos, sfi, force_shex, done);
		if (!section.empty()) {
			sections.emplace_back(std::move(section));
		}
	}

	if (!done) {
        spdlog::info("Did not find an assembly text section!");
        return vector<uint8_t>{};
	}

	if (sfi) {
		sections.emplace_front(std::move(serialise_subshader_feature_info_section(sfi)));
        spdlog::info("Inserted Subshader Feature Info section: {:x}", sfi);
	}
	return serialise_shader_binary(sections);
}

std::vector<uint8_t> AssembleFluganWithSignatureParsing(const std::string& assembly, std::list<AssemblerParseError>& parse_errors) 
{
	// Flugan's assembler normally cheats and reuses sections from the
	// original binary when replacing a shader from the game, but that
	// restricts what modifications we can do and is not an option when
	// assembling a stand-alone shader. Let's parse the missing sections
	// ourselves and manufacture a binary shader with those section to pass
	// to Flugan's assembler. Later we should refactor this into the
	// assembler itself.
	auto manufactured_bytecode = manufacture_shader_binary(assembly);
    if (manufactured_bytecode.empty())
		return std::vector<uint8_t>{};

	return assembler(assembly, manufactured_bytecode, parse_errors);
}

vector<uint8_t> AssembleFluganWithOptionalSignatureParsing(const std::string &sourceCode, bool assemble_signatures, const std::vector<uint8_t> &orig_bytecode, std::list<AssemblerParseError> &parse_errors)
{
	if (!assemble_signatures)
		return assembler(sourceCode, orig_bytecode, parse_errors);

	return AssembleFluganWithSignatureParsing(sourceCode, parse_errors);
}

// :alex:
// 64 bit magic FNV-0 and FNV-1 prime
static const uint64_t FNV_64_PRIME = 0x100000001b3ULL;
static uint64_t fnv_64_buf(const void* buf, size_t len) 
{
    uint64_t hval = 0u;
    unsigned const char* bp = (unsigned const char*)buf; /* start of buffer */
    unsigned const char* be = bp + len;                  /* beyond end of buffer */

    // FNV-1 hash each octet of the buffer
    while (bp < be) {
        // multiply by the 64 bit FNV magic prime mod 2^64 */
        hval *= FNV_64_PRIME;
        // xor the bottom with the current octet
        hval ^= (uint64_t)*bp++;
    }
    return hval;
}

// :alex:
uint64_t hash_shader(const void* pShaderBytecode, uint64_t BytecodeLength) 
{
    uint64_t hash = fnv_64_buf(pShaderBytecode, BytecodeLength);
    spdlog::info("       FNV hash = {:x}", hash);
    return hash;
}

// :alex:
std::string BinaryToAsmText(const void* pShaderBytecode, size_t BytecodeLength, int hexdump) 
{
    string comments;
    vector<uint8_t> byteCode(BytecodeLength);
    vector<uint8_t> disassembly;
    HRESULT r;

    memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

    r = disassembler(&byteCode, &disassembly, comments.c_str(), hexdump);
    if (FAILED(r)) {
        spdlog::info("  disassembly failed. Error: {}", r);
        return "";
    }

    return string(disassembly.begin(), disassembly.end());
}

// :alex:
std::vector<uint8_t> ReplaceASMShader(const uint64_t hash, const char* pShaderType, const void* pShaderBytecode, uint64_t BytecodeLength)
{
    std::vector<uint8_t> replacementShader;
    const std::filesystem::path final_path = Framework::getShaderPath(hash, pShaderType, "shaders").string();

	// matching shader replacement file available?
    std::ifstream f{final_path.string()};
    if (f) {
        spdlog::info("    Replacement ASM shader found. Assembling replacement ASM code.");
        
		auto fileSize = std::filesystem::file_size(final_path);
        std::string sourceCode(fileSize, '\0');
        f.read(sourceCode.data(), fileSize);
        spdlog::info("    Asm source code loaded. Size = {}", sourceCode.size());

        vector<uint8_t> byteCode(BytecodeLength);
        memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

        // Assemble to binary
        try {
            std::list<AssemblerParseError> parse_errors;
            std::vector<uint8_t> origByteCode(BytecodeLength);
            memcpy(origByteCode.data(), pShaderBytecode, BytecodeLength);
            replacementShader = AssembleFluganWithOptionalSignatureParsing(sourceCode, true, origByteCode, parse_errors);
            for (auto& parse_error : parse_errors) {
                spdlog::warn("{}: {}", final_path.filename().string(), parse_error.what());
            }
            if (!replacementShader.empty()) {
                return replacementShader;
            }
        } catch (const exception& e) {
            spdlog::warn("Error assembling {}: {}", final_path.filename().string(), e.what());
        }
    }

	// try regex replacement
    if (!Framework::m_regex_ps.empty()) {
        std::string disasm{BinaryToAsmText(pShaderBytecode, BytecodeLength, false)};
        if (Framework::m_regex_failed_shaders.find(hash) == Framework::m_regex_failed_shaders.end()) {
            std::string replacementSource;
            for (auto& regEx : Framework::m_regex_ps) {
                if (disasm.find_first_of(regEx.m_search) == std::string::npos)
                    continue;
                // At a minimum we want \n to be translated in the replace string, which needs extended substitution processing to be
                // enabled.
                auto match_data = pcre2_match_data_create_from_pattern(regEx.m_regex, NULL);
                auto output_size = disasm.length() + regEx.m_replacement.length() + 1024;
                std::string buf(output_size, '\0');
                auto rc = pcre2_substitute(regEx.m_regex, (PCRE2_SPTR)disasm.c_str(), disasm.length(), 0,
                    PCRE2_SUBSTITUTE_EXTENDED | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH, match_data, NULL, (PCRE2_SPTR)regEx.m_replacement.c_str(),
                    regEx.m_replacement.length(), (PCRE2_UCHAR8*)buf.data(), &output_size);
                pcre2_match_data_free(match_data);
                if (rc < 0) {
                    spdlog::warn("Error regex replace #{}", rc);
                    continue;
                }
                if (rc == 0) {
                    // not found
                    continue;
                }
                replacementSource.swap(buf);
                break;
            }
            if (!replacementSource.empty()) {
                // Assemble to binary
                try {
                    std::list<AssemblerParseError> parse_errors;
                    std::vector<uint8_t> origByteCode(BytecodeLength);
                    memcpy(origByteCode.data(), pShaderBytecode, BytecodeLength);
                    replacementShader = AssembleFluganWithOptionalSignatureParsing(replacementSource, true, origByteCode, parse_errors);
                    for (auto& parse_error : parse_errors) {
                        spdlog::warn("{}: {}", final_path.filename().string(), parse_error.what());
                    }
                    if (!replacementShader.empty()) {
                        return replacementShader;
                    }
                } catch (const exception& e) {
                    spdlog::warn("Error assembling {}: {}", final_path.filename().string(), e.what());
                }
            }
            Framework::m_regex_failed_shaders.insert(hash);
        }
    }

    return replacementShader;
}
