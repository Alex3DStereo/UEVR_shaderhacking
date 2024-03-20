#include <algorithm>
#include <spdlog/spdlog.h>
#include <utility/Thread.hpp>
#include <utility/Module.hpp>
#include <fstream> // :alex:

#include <safetyhook/thread_freezer.hpp>

#include "WindowFilter.hpp"
#include "Framework.hpp"

#include "D3D11Hook.hpp"

#include "shader/Shaders.h" // :alex:

using namespace std;

static D3D11Hook* g_d3d11_hook = nullptr;

// :alex:
std::unique_ptr<PointerHook> D3D11Hook::m_create_pixel_shader_hook; 
std::unordered_set<uint32_t> D3D11Hook::m_dumped_shaders;

D3D11Hook::~D3D11Hook() {
    unhook();
}

bool D3D11Hook::hook() {
    spdlog::info("Hooking D3D11");

    g_d3d11_hook = this;

    HWND h_wnd = GetDesktopWindow();
    IDXGISwapChain* swap_chain = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;

    D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_11_0;
    DXGI_SWAP_CHAIN_DESC swap_chain_desc;

    ZeroMemory(&swap_chain_desc, sizeof(swap_chain_desc));

    swap_chain_desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_chain_desc.BufferCount = 1;
    swap_chain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_desc.OutputWindow = h_wnd;
    swap_chain_desc.SampleDesc.Count = 1;
    swap_chain_desc.Windowed = TRUE;
    swap_chain_desc.BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
    swap_chain_desc.BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
    swap_chain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const auto original_bytes = utility::get_original_bytes(&D3D11CreateDeviceAndSwapChain);

    // Temporarily unhook D3D11CreateDeviceAndSwapChain
    // it allows compatibility with ReShade and other overlays that hook it
    // this is just a dummy device anyways, we don't want the other overlays to be able to use it
    if (original_bytes) {
        spdlog::info("D3D11CreateDeviceAndSwapChain appears to be hooked, temporarily unhooking");

        std::vector<uint8_t> hooked_bytes(original_bytes->size());
        memcpy(hooked_bytes.data(), &D3D11CreateDeviceAndSwapChain, original_bytes->size());

        ProtectionOverride protection_override{ &D3D11CreateDeviceAndSwapChain, original_bytes->size(), PAGE_EXECUTE_READWRITE };
        memcpy(&D3D11CreateDeviceAndSwapChain, original_bytes->data(), original_bytes->size());
        
        if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_NULL, nullptr, 0, &feature_level, 1, D3D11_SDK_VERSION,
                &swap_chain_desc, &swap_chain, &device, nullptr, &context))) 
        {
            spdlog::error("Failed to create D3D11 device");
            memcpy(&D3D11CreateDeviceAndSwapChain, hooked_bytes.data(), hooked_bytes.size());
            return false;
        }
        
        spdlog::info("Restoring hooked bytes for D3D11CreateDeviceAndSwapChain");
        memcpy(&D3D11CreateDeviceAndSwapChain, hooked_bytes.data(), hooked_bytes.size());
    } else {
        if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_NULL, nullptr, 0, &feature_level, 1, D3D11_SDK_VERSION,
                &swap_chain_desc, &swap_chain, &device, nullptr, &context))) 
        {
            spdlog::error("Failed to create D3D11 device");
            return false;
        }
    }

    try {
        safetyhook::execute_while_frozen([&] {
            m_present_hook.reset();
            m_resize_buffers_hook.reset();            
            // m_create_pixel_shader_hook.reset(); // :alex: do not rehook shader hooks

            auto& present_fn = (*(void***)swap_chain)[8];
            auto& resize_buffers_fn = (*(void***)swap_chain)[13];
            auto& create_pixel_shader_fn = (*(void***)device)[15]; // :alex:

            m_present_hook = std::make_unique<PointerHook>(&present_fn, (void*)&D3D11Hook::present);
            m_resize_buffers_hook = std::make_unique<PointerHook>(&resize_buffers_fn, (void*)&D3D11Hook::resize_buffers);
            // :alex:
            if (!m_create_pixel_shader_hook) {
                m_create_pixel_shader_hook = std::make_unique<PointerHook>(&create_pixel_shader_fn, (void*)&D3D11Hook::create_pixel_shader);
            }

            m_hooked = true;
        });
    } catch (const std::exception& e) {
        spdlog::error("Failed to hook D3D11: {}", e.what());
        m_hooked = false;
    }

    device->Release();
    context->Release();
    swap_chain->Release();
    return m_hooked;
}

bool D3D11Hook::unhook() {
    if (!m_hooked) {
        return true;
    }

    spdlog::info("Unhooking D3D11");

    // :alex: leave shader hooks intact
    if (m_present_hook->remove() && m_resize_buffers_hook->remove() /* && m_create_pixel_shader_hook->remove() */) {
        m_hooked = false;
        return true;
    }

    return false;
}

thread_local bool g_inside_d3d11_present = false;
HRESULT last_d3d11_present_result = S_OK;

HRESULT WINAPI D3D11Hook::present(IDXGISwapChain* swap_chain, UINT sync_interval, UINT flags) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    auto d3d11 = g_d3d11_hook;

    // This line must be called before calling our detour function because we might have to unhook the function inside our detour.
    auto present_fn = d3d11->m_present_hook->get_original<decltype(D3D11Hook::present)*>();

    DXGI_SWAP_CHAIN_DESC swap_desc{};
    swap_chain->GetDesc(&swap_desc);

    if (WindowFilter::get().is_filtered(swap_desc.OutputWindow)) {
        return present_fn(swap_chain, sync_interval, flags);
    }

    d3d11->m_inside_present = true;

    if (d3d11->m_swapchain_0 == nullptr) {
        d3d11->m_swapchain_0 = swap_chain;
        d3d11->m_swap_chain = swap_chain;
    } else if (d3d11->m_swapchain_1 == nullptr && swap_chain != d3d11->m_swapchain_0) {
        d3d11->m_swapchain_1 = swap_chain;
    }

    /*if (d3d11->m_swap_chain != d3d11->m_swapchain_0) {
        d3d11->m_inside_present = false;
        return present_fn(swap_chain, sync_interval, flags);
    }*/

    swap_chain->GetDevice(__uuidof(d3d11->m_device), (void**)&d3d11->m_device);

    /*if (d3d11->m_set_render_targets_hook == nullptr) {
        ComPtr<ID3D11DeviceContext> context{};

        d3d11->m_device->GetImmediateContext(&context);
        auto& set_render_targets_fn = (*(void***)context.Get())[33];
        d3d11->m_set_render_targets_hook = std::make_unique<PointerHook>(&set_render_targets_fn, (void*)&set_render_targets);
        OutputDebugString("Hooked ID3D11DeviceContext::SetRenderTargets");
    }*/

    /*if (GetAsyncKeyState(VK_INSERT) & 1) {
        OutputDebugString(fmt::format("Depth stencil @ {:p} used", (void*)d3d11->m_last_depthstencil_used.Get()).c_str());
    }*/

    // Restore the original bytes
    // if an infinite loop occurs, this will prevent the game from crashing
    // while keeping our hook intact
    if (g_inside_d3d11_present) {
        auto original_bytes = utility::get_original_bytes(Address{present_fn});

        if (original_bytes) {
            ProtectionOverride protection_override{present_fn, original_bytes->size(), PAGE_EXECUTE_READWRITE};

            memcpy(present_fn, original_bytes->data(), original_bytes->size());

            spdlog::info("Present fixed");
        }

        return last_d3d11_present_result;
    }

    if (d3d11->m_on_present) {
        d3d11->m_on_present(*d3d11);

        if (d3d11->m_next_present_interval) {
            sync_interval = *d3d11->m_next_present_interval;
            d3d11->m_next_present_interval = std::nullopt;

            if (sync_interval == 0) {
                BOOL is_fullscreen = 0;
                swap_chain->GetFullscreenState(&is_fullscreen, nullptr);
                flags &= ~DXGI_PRESENT_DO_NOT_SEQUENCE;

                if (!is_fullscreen && (swap_desc.Flags & DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING) != 0) {
                    flags |= DXGI_PRESENT_ALLOW_TEARING;
                }
            }
        }
    }

    HRESULT result = S_OK;
    g_inside_d3d11_present = true;

    if (!d3d11->m_ignore_next_present) {
        result = present_fn(swap_chain, sync_interval, flags);
        last_d3d11_present_result = result;
    } else {
        d3d11->m_ignore_next_present = false;
        last_d3d11_present_result = S_OK;
    }

    g_inside_d3d11_present = false;

    if (d3d11->m_on_post_present) {
        d3d11->m_on_post_present(*d3d11);
    }

    d3d11->m_last_depthstencil_used.Reset();
    d3d11->m_inside_present = false;

    return result;
}

thread_local bool g_inside_d3d11_resize_buffers = false;
HRESULT last_d3d11_resize_buffers_result = S_OK;

HRESULT WINAPI D3D11Hook::resize_buffers(
    IDXGISwapChain* swap_chain, UINT buffer_count, UINT width, UINT height, DXGI_FORMAT new_format, UINT swap_chain_flags) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    auto d3d11 = g_d3d11_hook;
    auto resize_buffers_fn = d3d11->m_resize_buffers_hook->get_original<decltype(D3D11Hook::resize_buffers)*>();

    DXGI_SWAP_CHAIN_DESC swap_desc{};
    swap_chain->GetDesc(&swap_desc);

    if (WindowFilter::get().is_filtered(swap_desc.OutputWindow)) {
        return resize_buffers_fn(swap_chain, buffer_count, width, height, new_format, swap_chain_flags);
    }

    d3d11->m_swap_chain = swap_chain;
    d3d11->m_swapchain_0 = nullptr;
    d3d11->m_swapchain_1 = nullptr;
    d3d11->m_last_depthstencil_used.Reset();

    if (d3d11->m_on_resize_buffers) {
        d3d11->m_on_resize_buffers(*d3d11, width, height);
    }

    if (g_inside_d3d11_resize_buffers) {
        auto original_bytes = utility::get_original_bytes(Address{resize_buffers_fn});

        if (original_bytes) {
            ProtectionOverride protection_override{resize_buffers_fn, original_bytes->size(), PAGE_EXECUTE_READWRITE};

            memcpy(resize_buffers_fn, original_bytes->data(), original_bytes->size());

            spdlog::info("Resize buffers fixed");
        }

        return last_d3d11_resize_buffers_result;
    }

    g_inside_d3d11_resize_buffers = true;

    last_d3d11_resize_buffers_result = resize_buffers_fn(swap_chain, buffer_count, width, height, new_format, swap_chain_flags);

    g_inside_d3d11_resize_buffers = false;

    return last_d3d11_resize_buffers_result;
}

void WINAPI D3D11Hook::set_render_targets(
    ID3D11DeviceContext* context, UINT num_views, ID3D11RenderTargetView* const* rtvs, ID3D11DepthStencilView* dsv) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    auto d3d11 = g_d3d11_hook;

    if (dsv != nullptr) {
        //auto obj_name = fmt::format("Depthstencil @ {:p}", (void*)d3d11->m_last_depthstencil_used.Get());
        //d3d11->m_last_depthstencil_used->SetPrivateData(WKPDID_D3DDebugObjectName, obj_name.size(), obj_name.c_str());
        //OutputDebugString(fmt::format("Depth stencil @ {:p} used", (void*)d3d11->m_last_depthstencil_used.Get()).c_str());

        D3D11_DEPTH_STENCIL_VIEW_DESC desc{};
        dsv->GetDesc(&desc);

        if (desc.Flags & D3D11_DSV_FLAG::D3D11_DSV_READ_ONLY_DEPTH) {
            dsv->GetResource((ID3D11Resource**)d3d11->m_last_depthstencil_used.GetAddressOf());

            //OutputDebugString(fmt::format("Flags: {}", desc.Flags).c_str());
            //OutputDebugString(fmt::format("Format: {}", desc.Format).c_str());
            //OutputDebugString(fmt::format("ViewDimension: {}", desc.ViewDimension).c_str());   
        }
    }

    auto set_render_targets_fn = d3d11->m_set_render_targets_hook->get_original<decltype(set_render_targets)*>();

    return set_render_targets_fn(context, num_views, rtvs, dsv);
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
static UINT64 hash_shader(const void* pShaderBytecode, SIZE_T BytecodeLength) 
{
    uint64_t hash = fnv_64_buf(pShaderBytecode, BytecodeLength);
    spdlog::info("       FNV hash = {:x}", hash);
    return hash;
}

// :alex:
static string BinaryToAsmText(const void* pShaderBytecode, size_t BytecodeLength, bool patch_cb_offsets, bool disassemble_undecipherable_data = true, int hexdump = 0, bool d3dcompiler_46_compat = true) 
{
    string comments;
    vector<uint8_t> byteCode(BytecodeLength);
    vector<uint8_t> disassembly;
    HRESULT r;

    memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

    r = disassembler(&byteCode, &disassembly, comments.c_str(), hexdump, d3dcompiler_46_compat, disassemble_undecipherable_data, patch_cb_offsets);
    if (FAILED(r)) {
        spdlog::info("  disassembly failed. Error: {}", r);
        return "";
    }

    return string(disassembly.begin(), disassembly.end());
}

// :alex:
static string GetShaderModel(const void* pShaderBytecode, size_t bytecodeLength) 
{
    string asmText = BinaryToAsmText(pShaderBytecode, bytecodeLength, false);
    if (asmText.empty())
        return "";

    // Read shader model. This is the first not commented line.
    char* pos = (char*)asmText.data();
    char* end = pos + asmText.size();
    while ((pos[0] == '/' || pos[0] == '\n') && pos < end) {
        while (pos[0] != 0x0a && pos < end)
            pos++;
        pos++;
    }
    // Extract model.
    char* eol = pos;
    while (eol[0] != 0x0a && pos < end)
        eol++;
    string shaderModel(pos, eol);

    return shaderModel;
}

static std::filesystem::path getShaderPath(const uint64_t hash, const char* pShaderType, const std::string &subfolder)
{
    char path[MAX_PATH];
    sprintf(path, "%016llx-%s.txt", hash, pShaderType);
    return Framework::get_persistent_dir(subfolder) / path;
}

// :alex:
static char *ReplaceASMShader(const uint64_t hash, const char* pShaderType, const void* pShaderBytecode, SIZE_T pBytecodeLength, SIZE_T& pCodeSize, string &pShaderModel) 
{
    char* pCode = nullptr;
    const std::filesystem::path final_path = getShaderPath(hash, pShaderType, "shaders").string();

    HANDLE f = CreateFile(final_path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    string shaderModel;
    if (f != INVALID_HANDLE_VALUE) {
        spdlog::info("    Replacement ASM shader found. Assembling replacement ASM code.");

        DWORD srcDataSize = GetFileSize(f, 0);
        vector<char> asmTextBytes(srcDataSize);
        DWORD readSize;
        if (!ReadFile(f, asmTextBytes.data(), srcDataSize, &readSize, 0) || srcDataSize != readSize)
            spdlog::info("    Error reading file.");
        CloseHandle(f);
        spdlog::info("    Asm source code loaded. Size = {}", srcDataSize);

        // Disassemble old shader to get shader model.
        shaderModel = GetShaderModel(pShaderBytecode, pBytecodeLength);
        if (shaderModel.empty()) {
            spdlog::info("    disassembly of original shader failed.");
        } else {
            // Any ASM shaders are reloading candidates, if moved to ShaderFixes
            pShaderModel = shaderModel;

            vector<uint8_t> byteCode(pBytecodeLength);
            memcpy(byteCode.data(), pShaderBytecode, pBytecodeLength);

            // Re-assemble the ASM text back to binary
            try {
                vector<AssemblerParseError> parse_errors;
                byteCode = AssembleFluganWithOptionalSignatureParsing(&asmTextBytes, true, &byteCode, &parse_errors);

                // Assuming the re-assembly worked, let's make it the active shader code.
                pCodeSize = byteCode.size();
                pCode = new char[pCodeSize];
                memcpy(pCode, byteCode.data(), pCodeSize);

                // Cache binary replacement.
                if (!parse_errors.empty()) {
                    // Parse errors are currently being treated as non-fatal on
                    // creation time replacement and ShaderRegex for backwards
                    // compatibility (live shader reload is fatal).
                    for (auto& parse_error : parse_errors)
                        spdlog::warn("{}: {}\n", final_path.filename().string(), parse_error.what());
                }
            } catch (const exception& e) {
                spdlog::warn("Error assembling {}: {}\n", final_path.filename().string(), e.what());
            }
        }
    }

    return pCode;
}


// :alex:
HRESULT WINAPI D3D11Hook::create_pixel_shader(ID3D11Device* device, const void* pShaderBytecode, uint64_t BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader) 
{
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    auto d3d11 = g_d3d11_hook;
    auto create_pixel_shader_fn = d3d11->m_create_pixel_shader_hook->get_original<decltype(create_pixel_shader)*>();

    if (!ppPixelShader || !pShaderBytecode) {
        // Let DX worry about the error code
        return create_pixel_shader_fn(device, pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
    }

	spdlog::info("D3D11Hook::create_pixel_shader called with BytecodeLength = {}", BytecodeLength);

    // Calculate hash
    uint64_t hash = hash_shader(pShaderBytecode, BytecodeLength);

	// look for replacement ASM text shaders.
    SIZE_T replaceShaderSize = 0;
    string shaderModel;
    char* replaceShader = ReplaceASMShader(hash, "ps", pShaderBytecode, BytecodeLength, replaceShaderSize, shaderModel);
    if (!replaceShader) {
        // dump unknown shader?
        if (Framework::shader_dump_enabled() && (m_dumped_shaders.find(hash) == m_dumped_shaders.end()))
        {
            m_dumped_shaders.insert(hash);
            const auto dumpPath = getShaderPath(hash, "ps", "dump");
            if (!std::filesystem::exists(dumpPath))
            {
                fstream outfile(dumpPath.string(), std::ios_base::out);
                outfile << BinaryToAsmText(pShaderBytecode, BytecodeLength, false);                
            }
        }
        // create original shader
        return create_pixel_shader_fn(device, pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
    }

    HRESULT hr = create_pixel_shader_fn(device, replaceShader, replaceShaderSize, pClassLinkage, ppPixelShader);
    if (hr == S_OK) {
        spdlog::info("    PS: hash = {:x}", hash);
    }

    spdlog::info("  returns result = {}", hr);
    return hr;
}
