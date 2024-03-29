#include <thread>
#include <future>
#include <unordered_set>
#include <fstream> // :alex:

#include <spdlog/spdlog.h>
#include <utility/Thread.hpp>
#include <utility/Module.hpp>

#include <safetyhook/thread_freezer.hpp>

#include "WindowFilter.hpp"
#include "Framework.hpp"

#include "D3D12Hook.hpp"

#include "shader/Shaders.h" // :alex:

static D3D12Hook* g_d3d12_hook = nullptr;

// :alex:
std::unordered_set<uint64_t> D3D12Hook::m_dumped_shaders;

D3D12Hook::~D3D12Hook() {
    unhook();
}

bool D3D12Hook::hook() {
    spdlog::info("Hooking D3D12");

    g_d3d12_hook = this;

    IDXGISwapChain1* swap_chain1{ nullptr };
    IDXGISwapChain3* swap_chain{ nullptr };
    ID3D12Device4* device{ nullptr };

    // :alex:
    // D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_11_0;
    D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_12_1;
    DXGI_SWAP_CHAIN_DESC1 swap_chain_desc1;

    ZeroMemory(&swap_chain_desc1, sizeof(swap_chain_desc1));

    swap_chain_desc1.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    swap_chain_desc1.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_desc1.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    swap_chain_desc1.BufferCount = 2;
    swap_chain_desc1.SampleDesc.Count = 1;
    swap_chain_desc1.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
    swap_chain_desc1.Width = 1;
    swap_chain_desc1.Height = 1;

    // Manually get D3D12CreateDevice export because the user may be running Windows 7
    const auto d3d12_module = LoadLibraryA("d3d12.dll");
    if (d3d12_module == nullptr) {
        spdlog::error("Failed to load d3d12.dll");
        return false;
    }

    auto d3d12_create_device = (decltype(D3D12CreateDevice)*)GetProcAddress(d3d12_module, "D3D12CreateDevice");
    if (d3d12_create_device == nullptr) {
        spdlog::error("Failed to get D3D12CreateDevice export");
        return false;
    }

    spdlog::info("Creating dummy device");

    // Get the original on-disk bytes of the D3D12CreateDevice export
    const auto original_bytes = utility::get_original_bytes(d3d12_create_device);

    // Temporarily unhook D3D12CreateDevice
    // it allows compatibility with ReShade and other overlays that hook it
    // this is just a dummy device anyways, we don't want the other overlays to be able to use it
    if (original_bytes) {
        spdlog::info("D3D12CreateDevice appears to be hooked, temporarily unhooking");

        std::vector<uint8_t> hooked_bytes(original_bytes->size());
        memcpy(hooked_bytes.data(), d3d12_create_device, original_bytes->size());

        ProtectionOverride protection_override{ d3d12_create_device, original_bytes->size(), PAGE_EXECUTE_READWRITE };
        memcpy(d3d12_create_device, original_bytes->data(), original_bytes->size());
        
        if (FAILED(d3d12_create_device(nullptr, feature_level, IID_PPV_ARGS(&device)))) {
            spdlog::error("Failed to create D3D12 Dummy device");
            memcpy(d3d12_create_device, hooked_bytes.data(), hooked_bytes.size());
            return false;
        }

        spdlog::info("Restoring hooked bytes for D3D12CreateDevice");
        memcpy(d3d12_create_device, hooked_bytes.data(), hooked_bytes.size());
    } else { // D3D12CreateDevice is not hooked
        if (FAILED(d3d12_create_device(nullptr, feature_level, IID_PPV_ARGS(&device)))) {
            spdlog::error("Failed to create D3D12 Dummy device");
            return false;
        }
    }

    spdlog::info("Dummy device: {:x}", (uintptr_t)device);

    // Manually get CreateDXGIFactory export because the user may be running Windows 7
    const auto dxgi_module = LoadLibraryA("dxgi.dll");
    if (dxgi_module == nullptr) {
        spdlog::error("Failed to load dxgi.dll");
        return false;
    }

    auto create_dxgi_factory = (decltype(CreateDXGIFactory)*)GetProcAddress(dxgi_module, "CreateDXGIFactory");

    if (create_dxgi_factory == nullptr) {
        spdlog::error("Failed to get CreateDXGIFactory export");
        return false;
    }

    spdlog::info("Creating dummy DXGI factory");

    IDXGIFactory4* factory{ nullptr };
    if (FAILED(create_dxgi_factory(IID_PPV_ARGS(&factory)))) {
        spdlog::error("Failed to create D3D12 Dummy DXGI Factory");
        return false;
    }

    D3D12_COMMAND_QUEUE_DESC queue_desc{};
    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queue_desc.Priority = 0;
    queue_desc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    queue_desc.NodeMask = 0;

    spdlog::info("Creating dummy command queue");

    ID3D12CommandQueue* command_queue{ nullptr };
    if (FAILED(device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&command_queue)))) {
        spdlog::error("Failed to create D3D12 Dummy Command Queue");
        return false;
    }

    spdlog::info("Creating dummy swapchain");

    // used in CreateSwapChainForHwnd fallback
    HWND hwnd = 0;
    WNDCLASSEX wc{};

    auto init_dummy_window = [&]() {
        // fallback to CreateSwapChainForHwnd
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = DefWindowProc;
        wc.cbClsExtra = 0;
        wc.cbWndExtra = 0;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hIcon = NULL;
        wc.hCursor = NULL;
        wc.hbrBackground = NULL;
        wc.lpszMenuName = NULL;
        wc.lpszClassName = TEXT("REFRAMEWORK_DX12_DUMMY");
        wc.hIconSm = NULL;

        ::RegisterClassEx(&wc);

        hwnd = ::CreateWindow(wc.lpszClassName, TEXT("REF DX Dummy Window"), WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, wc.hInstance, NULL);

        swap_chain_desc1.BufferCount = 3;
        swap_chain_desc1.Width = 0;
        swap_chain_desc1.Height = 0;
        swap_chain_desc1.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        swap_chain_desc1.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
        swap_chain_desc1.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        swap_chain_desc1.SampleDesc.Count = 1;
        swap_chain_desc1.SampleDesc.Quality = 0;
        swap_chain_desc1.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        swap_chain_desc1.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
        swap_chain_desc1.Scaling = DXGI_SCALING_STRETCH;
        swap_chain_desc1.Stereo = FALSE;
    };

    std::vector<std::function<bool ()>> swapchain_attempts{
        // we call CreateSwapChainForComposition instead of CreateSwapChainForHwnd
        // because some overlays will have hooks on CreateSwapChainForHwnd
        // and all we're doing is creating a dummy swapchain
        // we don't want to screw up the overlay
        [&]() {
            return !FAILED(factory->CreateSwapChainForComposition(command_queue, &swap_chain_desc1, nullptr, &swap_chain1));
        },
        [&]() {
            init_dummy_window();

            return !FAILED(factory->CreateSwapChainForHwnd(command_queue, hwnd, &swap_chain_desc1, nullptr, nullptr, &swap_chain1));
        },
        [&]() {
            return !FAILED(factory->CreateSwapChainForHwnd(command_queue, GetDesktopWindow(), &swap_chain_desc1, nullptr, nullptr, &swap_chain1));
        },
    };

    bool any_succeed = false;

    for (auto i = 0; i < swapchain_attempts.size(); i++) {
        auto& attempt = swapchain_attempts[i];
        
        try {
            spdlog::info("Trying swapchain attempt {}", i);

            if (attempt()) {
                spdlog::info("Created dummy swapchain on attempt {}", i);
                any_succeed = true;
                break;
            }
        } catch (std::exception& e) {
            spdlog::error("Failed to create dummy swapchain on attempt {}: {}", i, e.what());
        } catch(...) {
            spdlog::error("Failed to create dummy swapchain on attempt {}: unknown exception", i);
        }

        spdlog::error("Attempt {} failed", i);
    }

    if (!any_succeed) {
        spdlog::error("Failed to create D3D12 Dummy Swap Chain");

        if (hwnd) {
            ::DestroyWindow(hwnd);
        }

        if (wc.lpszClassName != nullptr) {
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        }

        return false;
    }

    spdlog::info("Querying dummy swapchain");

    if (FAILED(swap_chain1->QueryInterface(IID_PPV_ARGS(&swap_chain)))) {
        spdlog::error("Failed to retrieve D3D12 DXGI SwapChain");
        return false;
    }

    spdlog::info("Finding command queue offset");

    // Find the command queue offset in the swapchain
    for (auto i = 0; i < 512 * sizeof(void*); i += sizeof(void*)) {
        const auto base = (uintptr_t)swap_chain1 + i;

        // reached the end
        if (IsBadReadPtr((void*)base, sizeof(void*))) {
            break;
        }

        auto data = *(ID3D12CommandQueue**)base;

        if (data == command_queue) {
            m_command_queue_offset = i;
            spdlog::info("Found command queue offset: {:x}", i);
            break;
        }
    }

    // Scan throughout the swapchain for a valid pointer to scan through
    // this is usually only necessary for Proton
    if (m_command_queue_offset == 0) {
        for (auto base = 0; base < 512 * sizeof(void*); base += sizeof(void*)) {
            const auto pre_scan_base = (uintptr_t)swap_chain1 + base;

            // reached the end
            if (IsBadReadPtr((void*)pre_scan_base, sizeof(void*))) {
                break;
            }

            const auto scan_base = *(uintptr_t*)pre_scan_base;

            if (scan_base == 0 || IsBadReadPtr((void*)scan_base, sizeof(void*))) {
                continue;
            }

            for (auto i = 0; i < 512 * sizeof(void*); i += sizeof(void*)) {
                const auto pre_data = scan_base + i;

                if (IsBadReadPtr((void*)pre_data, sizeof(void*))) {
                    break;
                }

                auto data = *(ID3D12CommandQueue**)pre_data;

                if (data == command_queue) {
                    m_using_proton_swapchain = true;
                    m_command_queue_offset = i;
                    m_proton_swapchain_offset = base;

                    spdlog::info("Proton potentially detected");
                    spdlog::info("Found command queue offset: {:x}", i);
                    break;
                }
            }

            if (m_using_proton_swapchain) {
                break;
            }
        }
    }

    if (m_command_queue_offset == 0) {
        spdlog::error("Failed to find command queue offset");
        return false;
    }

    try {
        safetyhook::execute_while_frozen([&] {
            spdlog::info("Initializing D3D12 hooks");  // :alex:
            m_present_hook.reset();
            m_swapchain_hook.reset();
            m_create_graphics_pipeline_state_hook.reset(); // :alex:
            m_create_pipeline_state_hook.reset(); // :alex:
            m_create_pipeline_library_hook.reset(); // :alex:

            m_is_phase_1 = true;

            auto& present_fn = (*(void***)swap_chain)[8]; // Present
            auto& create_graphics_pipeline_state_fn = (*(void***)device)[10];     // :alex:
            auto& create_pipeline_state_fn = (*(void***)device)[47];          // :alex:
            auto& create_pipeline_library_fn = (*(void***)device)[44];            // :alex:
            m_present_hook = std::make_unique<PointerHook>(&present_fn, (void*)&D3D12Hook::present);
            spdlog::info("PointerHook D3D12Device::CreateGraphicsPipelineState"); // :alex:
            m_create_graphics_pipeline_state_hook = std::make_unique<PointerHook>(&create_graphics_pipeline_state_fn, (void*)&D3D12Hook::create_graphics_pipeline_state); // :alex:
            spdlog::info("PointerHook D3D12Device::CreatePipelineState"); // :alex:
            m_create_pipeline_state_hook = std::make_unique<PointerHook>(&create_pipeline_state_fn, (void*)&D3D12Hook::create_pipeline_state); // :alex:
            spdlog::info("PointerHook D3D12Device::CreatePipelineLibrary"); // :alex:
            m_create_pipeline_library_hook = std::make_unique<PointerHook>(&create_pipeline_library_fn, (void*)&D3D12Hook::create_pipeline_library); // :alex:
            m_hooked = true;
        });
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize hooks: {}", e.what());
        m_hooked = false;
    }

    device->Release();
    command_queue->Release();
    factory->Release();
    swap_chain1->Release();
    swap_chain->Release();

    if (hwnd) {
        ::DestroyWindow(hwnd);
    }

    if (wc.lpszClassName != nullptr) {
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    }

    return m_hooked;
}

bool D3D12Hook::unhook() {
    if (!m_hooked) {
        return true;
    }

    spdlog::info("Unhooking D3D12");

    m_present_hook.reset();
    m_swapchain_hook.reset();
    m_create_graphics_pipeline_state_hook.reset(); // :alex:
    m_create_pipeline_state_hook.reset(); // :alex:
    m_create_pipeline_library_hook.reset(); // :alex:

    m_hooked = false;
    m_is_phase_1 = true;

    return true;
}

thread_local int32_t g_present_depth = 0;

HRESULT WINAPI D3D12Hook::present(IDXGISwapChain3* swap_chain, UINT sync_interval, UINT flags) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    auto d3d12 = g_d3d12_hook;

    HWND swapchain_wnd{nullptr};
    swap_chain->GetHwnd(&swapchain_wnd);

    decltype(D3D12Hook::present)* present_fn{nullptr};

    // if (d3d12->m_is_phase_1) {
    present_fn = d3d12->m_present_hook->get_original<decltype(D3D12Hook::present)*>();
    /*} else {
        present_fn = d3d12->m_swapchain_hook->get_method<decltype(D3D12Hook::present)*>(8);
    }*/

    if (d3d12->m_is_phase_1 && WindowFilter::get().is_filtered(swapchain_wnd)) {
        return present_fn(swap_chain, sync_interval, flags);
    }

    if (!d3d12->m_is_phase_1 && swap_chain != d3d12->m_swapchain_hook->get_instance()) {
        const auto og_instance = d3d12->m_swapchain_hook->get_instance();

        // If the original swapchain instance is invalid, then we should not proceed, and rehook the swapchain
        if (IsBadReadPtr(og_instance, sizeof(void*)) || IsBadReadPtr(og_instance.deref(), sizeof(void*))) {
            spdlog::error("Bad read pointer for original swapchain instance, re-hooking");
            d3d12->m_is_phase_1 = true;
        }

        if (!d3d12->m_is_phase_1) {
            return present_fn(swap_chain, sync_interval, flags);
        }
    }

    // :alex:
    ID3D12Device4* currentDevice = nullptr;
    swap_chain->GetDevice(IID_PPV_ARGS(&currentDevice));
    if (d3d12->m_device != nullptr && d3d12->m_device != currentDevice) {
        d3d12->m_device->Release();
        d3d12->m_device = nullptr;
        spdlog::info("D3D12Hook::present ID3D12Device4 device changed");
    }
    d3d12->m_device = currentDevice;

    if (d3d12->m_is_phase_1) {
        //d3d12->m_present_hook.reset();
        d3d12->m_swapchain_hook.reset();

        // vtable hook the swapchain instead of global hooking
        // this seems safer for whatever reason
        // if we globally hook the vtable pointers, it causes all sorts of weird conflicts with other hooks
        // dont hook present though via this hook so other hooks dont get confused
        d3d12->m_swapchain_hook = std::make_unique<VtableHook>(swap_chain);
        //d3d12->m_swapchain_hook->hook_method(8, (uintptr_t)&D3D12Hook::present);
        d3d12->m_swapchain_hook->hook_method(13, (uintptr_t)&D3D12Hook::resize_buffers);
        d3d12->m_swapchain_hook->hook_method(14, (uintptr_t)&D3D12Hook::resize_target);
        d3d12->m_is_phase_1 = false;
    }

    d3d12->m_inside_present = true;
    d3d12->m_swap_chain = swap_chain;

    // :alex:
    // swap_chain->GetDevice(IID_PPV_ARGS(&d3d12->m_device));

    if (d3d12->m_device != nullptr) {
        if (d3d12->m_using_proton_swapchain) {
            const auto real_swapchain = *(uintptr_t*)((uintptr_t)swap_chain + d3d12->m_proton_swapchain_offset);
            d3d12->m_command_queue = *(ID3D12CommandQueue**)(real_swapchain + d3d12->m_command_queue_offset);
        } else {
            d3d12->m_command_queue = *(ID3D12CommandQueue**)((uintptr_t)swap_chain + d3d12->m_command_queue_offset);
        }
    }

    if (d3d12->m_swapchain_0 == nullptr) {
        d3d12->m_swapchain_0 = swap_chain;
    } else if (d3d12->m_swapchain_1 == nullptr && swap_chain != d3d12->m_swapchain_0) {
        d3d12->m_swapchain_1 = swap_chain;
    }
    
    // Restore the original bytes
    // if an infinite loop occurs, this will prevent the game from crashing
    // while keeping our hook intact
    if (g_present_depth > 0) {
        auto original_bytes = utility::get_original_bytes(Address{present_fn});

        if (original_bytes) {
            ProtectionOverride protection_override{present_fn, original_bytes->size(), PAGE_EXECUTE_READWRITE};

            memcpy(present_fn, original_bytes->data(), original_bytes->size());

            spdlog::info("Present fixed");
        }

        if ((uintptr_t)present_fn != (uintptr_t)D3D12Hook::present && g_present_depth == 1) {
            spdlog::info("Attempting to call real present function");

            ++g_present_depth;
            const auto result = present_fn(swap_chain, sync_interval, flags);
            --g_present_depth;

            if (result != S_OK) {
                spdlog::error("Present failed: {:x}", result);
            }

            return result;
        }

        spdlog::info("Just returning S_OK");
        return S_OK;
    }

    if (d3d12->m_on_present) {
        d3d12->m_on_present(*d3d12);

        if (d3d12->m_next_present_interval) {
            sync_interval = *d3d12->m_next_present_interval;
            d3d12->m_next_present_interval = std::nullopt;

            if (sync_interval == 0) {
                BOOL is_fullscreen = 0;
                swap_chain->GetFullscreenState(&is_fullscreen, nullptr);
                flags &= ~DXGI_PRESENT_DO_NOT_SEQUENCE;

                DXGI_SWAP_CHAIN_DESC swap_desc{};
                swap_chain->GetDesc(&swap_desc);

                if (!is_fullscreen && (swap_desc.Flags & DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING) != 0) {
                    flags |= DXGI_PRESENT_ALLOW_TEARING;
                }
            }
        }
    }

    ++g_present_depth;

    auto result = S_OK;
    
    if (!d3d12->m_ignore_next_present) {
        result = present_fn(swap_chain, sync_interval, flags);

        if (result != S_OK) {
            spdlog::error("Present failed: {:x}", result);
        }
    } else {
        d3d12->m_ignore_next_present = false;
    }

    --g_present_depth;

    if (d3d12->m_on_post_present) {
        d3d12->m_on_post_present(*d3d12);
    }

    d3d12->m_inside_present = false;
    
    return result;
}

thread_local int32_t g_resize_buffers_depth = 0;

HRESULT WINAPI D3D12Hook::resize_buffers(IDXGISwapChain3* swap_chain, UINT buffer_count, UINT width, UINT height, DXGI_FORMAT new_format, UINT swap_chain_flags) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    spdlog::info("D3D12 resize buffers called");
    spdlog::info(" Parameters: buffer_count {} width {} height {} new_format {} swap_chain_flags {}", buffer_count, width, height, new_format, swap_chain_flags);

    auto d3d12 = g_d3d12_hook;
    //auto& hook = d3d12->m_resize_buffers_hook;
    //auto resize_buffers_fn = hook->get_original<decltype(D3D12Hook::resize_buffers)*>();

    HWND swapchain_wnd{nullptr};
    swap_chain->GetHwnd(&swapchain_wnd);

    auto resize_buffers_fn = d3d12->m_swapchain_hook->get_method<decltype(D3D12Hook::resize_buffers)*>(13);

    if (WindowFilter::get().is_filtered(swapchain_wnd)) {
        return resize_buffers_fn(swap_chain, buffer_count, width, height, new_format, swap_chain_flags);
    }

    d3d12->m_display_width = width;
    d3d12->m_display_height = height;

    if (g_resize_buffers_depth > 0) {
        auto original_bytes = utility::get_original_bytes(Address{resize_buffers_fn});

        if (original_bytes) {
            ProtectionOverride protection_override{resize_buffers_fn, original_bytes->size(), PAGE_EXECUTE_READWRITE};

            memcpy(resize_buffers_fn, original_bytes->data(), original_bytes->size());

            spdlog::info("Resize buffers fixed");
        }

        if ((uintptr_t)resize_buffers_fn != (uintptr_t)&D3D12Hook::resize_buffers && g_resize_buffers_depth == 1) {
            spdlog::info("Attempting to call the real resize buffers function");

            ++g_resize_buffers_depth;
            const auto result = resize_buffers_fn(swap_chain, buffer_count, width, height, new_format, swap_chain_flags);
            --g_resize_buffers_depth;

            if (result != S_OK) {
                spdlog::error("Resize buffers failed: {:x}", result);
            }

            return result;
        } else {
            spdlog::info("Just returning S_OK");
            return S_OK;
        }
    }

    if (d3d12->m_on_resize_buffers) {
        d3d12->m_on_resize_buffers(*d3d12, width, height);
    }

    ++g_resize_buffers_depth;

    const auto result = resize_buffers_fn(swap_chain, buffer_count, width, height, new_format, swap_chain_flags);
    
    if (result != S_OK) {
        spdlog::error("Resize buffers failed: {:x}", result);
    }

    --g_resize_buffers_depth;

    return result;
}

thread_local int32_t g_resize_target_depth = 0;

HRESULT WINAPI D3D12Hook::resize_target(IDXGISwapChain3* swap_chain, const DXGI_MODE_DESC* new_target_parameters) {
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};

    spdlog::info("D3D12 resize target called");
    spdlog::info(" Parameters: new_target_parameters {:x}", (uintptr_t)new_target_parameters);

    auto d3d12 = g_d3d12_hook;
    //auto resize_target_fn = d3d12->m_resize_target_hook->get_original<decltype(D3D12Hook::resize_target)*>();

    HWND swapchain_wnd{nullptr};
    swap_chain->GetHwnd(&swapchain_wnd);

    auto resize_target_fn = d3d12->m_swapchain_hook->get_method<decltype(D3D12Hook::resize_target)*>(14);

    if (WindowFilter::get().is_filtered(swapchain_wnd)) {
        return resize_target_fn(swap_chain, new_target_parameters);
    }

    d3d12->m_render_width = new_target_parameters->Width;
    d3d12->m_render_height = new_target_parameters->Height;

    // Restore the original code to the resize_buffers function.
    if (g_resize_target_depth > 0) {
        auto original_bytes = utility::get_original_bytes(Address{resize_target_fn});

        if (original_bytes) {
            ProtectionOverride protection_override{resize_target_fn, original_bytes->size(), PAGE_EXECUTE_READWRITE};

            memcpy(resize_target_fn, original_bytes->data(), original_bytes->size());

            spdlog::info("Resize target fixed");
        }

        if ((uintptr_t)resize_target_fn != (uintptr_t)&D3D12Hook::resize_target && g_resize_target_depth == 1) {
            spdlog::info("Attempting to call the real resize target function");

            ++g_resize_target_depth;
            const auto result = resize_target_fn(swap_chain, new_target_parameters);
            --g_resize_target_depth;

            if (result != S_OK) {
                spdlog::error("Resize target failed: {:x}", result);
            }

            return result;
        } else {
            spdlog::info("Just returning S_OK");
            return S_OK;
        }
    }

    if (d3d12->m_on_resize_target) {
        d3d12->m_on_resize_target(*d3d12, new_target_parameters->Width, new_target_parameters->Height);
    }

    ++g_resize_target_depth;

    const auto result = resize_target_fn(swap_chain, new_target_parameters);
    
    if (result != S_OK) {
        spdlog::error("Resize target failed: {:x}", result);
    }

    --g_resize_target_depth;

    return result;
}

/*HRESULT WINAPI D3D12Hook::create_swap_chain(IDXGIFactory4* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC* desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* p_fullscreen_desc, IDXGIOutput* p_restrict_to_output, IDXGISwapChain** swap_chain)
{
    spdlog::info("D3D12 create swapchain called");

    auto d3d12 = g_d3d12_hook;

    d3d12->m_command_queue = (ID3D12CommandQueue*)device;
    
    if (d3d12->m_on_create_swap_chain) {
        d3d12->m_on_create_swap_chain(*d3d12);
    }

    auto create_swap_chain_fn = d3d12->m_create_swap_chain_hook->get_original<decltype(D3D12Hook::create_swap_chain)>();

    return create_swap_chain_fn(factory, device, hwnd, desc, p_fullscreen_desc, p_restrict_to_output, swap_chain);
}*/

HRESULT WINAPI D3D12Hook::create_graphics_pipeline_state(ID3D12Device4* device, const D3D12_GRAPHICS_PIPELINE_STATE_DESC* pDesc, REFIID riid, void** ppPipelineState)
{
    auto d3d12 = g_d3d12_hook;
    auto create_graphics_pipeline_state_fn = d3d12->m_create_graphics_pipeline_state_hook->get_original<decltype(D3D12Hook::create_graphics_pipeline_state)*>();

    if (pDesc == nullptr || pDesc->PS.pShaderBytecode == nullptr) {
        return create_graphics_pipeline_state_fn(device, pDesc, riid, ppPipelineState);
    }
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};
    spdlog::info("D3D12Hook::create_graphics_pipeline_state called with PS->BytecodeLength = {}", pDesc->PS.BytecodeLength);

    // Calculate hash
    uint64_t hash = hash_shader(pDesc->PS.pShaderBytecode, pDesc->PS.BytecodeLength);

    // look for replacement ASM text shaders.
    SIZE_T replaceShaderSize = 0;
    char* replaceShader = ReplaceASMShader(hash, "ps", pDesc->PS.pShaderBytecode, pDesc->PS.BytecodeLength, replaceShaderSize);
    if (!replaceShader) {
        // dump unknown shader?
        if (Framework::shader_dump_enabled() && (m_dumped_shaders.find(hash) == m_dumped_shaders.end())) {
            m_dumped_shaders.insert(hash);
            const auto dumpPath = Framework::getShaderPath(hash, "ps", "dump");
            if (!std::filesystem::exists(dumpPath)) {
                std::fstream outfile(dumpPath.string(), std::ios_base::out);
                outfile << BinaryToAsmText(pDesc->PS.pShaderBytecode, pDesc->PS.BytecodeLength, false);
            }
        }
        // create original shader
        return create_graphics_pipeline_state_fn(device, pDesc, riid, ppPipelineState);
    }

    const void* const origShaderBytecode = pDesc->PS.pShaderBytecode;
    const uint64_t origShaderSize = pDesc->PS.BytecodeLength;
    const_cast<D3D12_GRAPHICS_PIPELINE_STATE_DESC*>(pDesc)->PS.pShaderBytecode = replaceShader;
    const_cast<D3D12_GRAPHICS_PIPELINE_STATE_DESC*>(pDesc)->PS.BytecodeLength = replaceShaderSize;
    HRESULT hr = create_graphics_pipeline_state_fn(device, pDesc, riid, ppPipelineState);
    const_cast<D3D12_GRAPHICS_PIPELINE_STATE_DESC*>(pDesc)->PS.pShaderBytecode = origShaderBytecode;
    const_cast<D3D12_GRAPHICS_PIPELINE_STATE_DESC*>(pDesc)->PS.BytecodeLength = origShaderSize;
    delete replaceShader;
    if (hr == S_OK) {
        spdlog::info("    PS: hash = {:x}", hash);
    }

    spdlog::info("  returns result = {}", hr);
    return hr;
}

HRESULT WINAPI D3D12Hook::create_pipeline_state(ID3D12Device4* device, const D3D12_PIPELINE_STATE_STREAM_DESC* pDesc, REFIID riid, void** ppPipelineState) 
{
    auto d3d12 = g_d3d12_hook;
    auto create_pipeline_state_fn = d3d12->m_create_pipeline_state_hook->get_original<decltype(D3D12Hook::create_pipeline_state)*>();

    if (device == nullptr || pDesc == nullptr) {
        // Let DX worry about the error code
        return create_pipeline_state_fn(device, pDesc, riid, ppPipelineState);
    }
    std::scoped_lock _{g_framework->get_hook_monitor_mutex()};
    spdlog::info("D3D12Hook::create_pipeline_state called");

    uint64_t pos = 0;
    uint8_t* const data = (uint8_t* const)pDesc->pPipelineStateSubobjectStream;
    const void** pixelShaderPtr = nullptr;
    uint64_t* pixelShaderSizePtr = 0ULL;
    const void* origPixelShader = nullptr;
    uint64_t origPixelShaderSize = 0ULL;
    uint64_t pixelShaderHash = 0ULL;
    while (pos < pDesc->SizeInBytes) {
        D3D12_PIPELINE_STATE_SUBOBJECT_TYPE type = *(D3D12_PIPELINE_STATE_SUBOBJECT_TYPE*)(data + pos);
//        spdlog::info(" type = {:x},{:x},{:x},{:x} {:x},{:x},{:x},{:x}", data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
//            data[pos + 4], data[pos + 5], data[pos + 6], data[pos+7]);
        pos += 4;
//        spdlog::info("type={}", type);
        switch (type) {
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_ROOT_SIGNATURE:
//            spdlog::info("D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_ROOT_SIGNATURE");
            pos += 8;
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_VS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_DS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_HS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_GS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_CS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_AS:
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_MS:
            pos += sizeof(D3D12_SHADER_BYTECODE);
//            spdlog::info("D3D12_SHADER_BYTECODE");
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_PS: {
            D3D12_SHADER_BYTECODE* desc_shader = (D3D12_SHADER_BYTECODE*)(data + pos + 4);
            spdlog::info("D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_PS ver={}, ptr={:x}, size={}", *(uint32_t*)(data+pos), (uint64_t)desc_shader->pShaderBytecode, desc_shader->BytecodeLength);
            pos += sizeof(D3D12_SHADER_BYTECODE) + 4;        

            //spdlog::info(" PS1 = {:x},{:x},{:x},{:x} {:x},{:x},{:x},{:x}", data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            //    data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]);
            //spdlog::info(" PS2 = {:x},{:x},{:x},{:x} {:x},{:x},{:x},{:x}", data[pos+8], data[pos + 9], data[pos + 10], data[pos + 11],
            //    data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]);
            
            if (desc_shader->pShaderBytecode != nullptr) {
                pixelShaderHash = hash_shader(desc_shader->pShaderBytecode, desc_shader->BytecodeLength);
                SIZE_T replacementShaderSize = 0;
                char* replacementShader = ReplaceASMShader(pixelShaderHash, "ps", desc_shader->pShaderBytecode, desc_shader->BytecodeLength, replacementShaderSize); 
                if (!replacementShader) {
                    // dump unknown shader?
                    if (Framework::shader_dump_enabled() && (m_dumped_shaders.find(pixelShaderHash) == m_dumped_shaders.end())) {
                        m_dumped_shaders.insert(pixelShaderHash);
                        const auto dumpPath = Framework::getShaderPath(pixelShaderHash, "ps", "dump");
                        if (!std::filesystem::exists(dumpPath)) {
                            std::fstream outfile(dumpPath.string(), std::ios_base::out | std::ios_base::binary);
                            outfile << BinaryToAsmText(desc_shader->pShaderBytecode, desc_shader->BytecodeLength, false);
                        }
                    }
                }
                else
                {
                    origPixelShaderSize = desc_shader->BytecodeLength;
                    origPixelShader = desc_shader->pShaderBytecode;
                    pixelShaderSizePtr = &desc_shader->BytecodeLength;
                    pixelShaderPtr = &desc_shader->pShaderBytecode;
                    desc_shader->pShaderBytecode = replacementShader;
                    desc_shader->BytecodeLength = replacementShaderSize;
                }
            }
            break;
        }
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_STREAM_OUTPUT:
            pos += sizeof(D3D12_STREAM_OUTPUT_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_BLEND:
            pos += sizeof(D3D12_BLEND_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_SAMPLE_MASK:
            pos += sizeof(UINT);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_RASTERIZER:
            pos += sizeof(D3D12_RASTERIZER_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_DEPTH_STENCIL:
            pos += sizeof(D3D12_DEPTH_STENCIL_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_INPUT_LAYOUT:
            pos += sizeof(D3D12_INPUT_LAYOUT_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_IB_STRIP_CUT_VALUE:
            pos += sizeof(D3D12_INDEX_BUFFER_STRIP_CUT_VALUE);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_PRIMITIVE_TOPOLOGY:
            pos += sizeof(D3D12_PRIMITIVE_TOPOLOGY_TYPE);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_RENDER_TARGET_FORMATS:
            pos += sizeof(D3D12_RT_FORMAT_ARRAY);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_DEPTH_STENCIL_FORMAT:
            pos += sizeof(DXGI_FORMAT);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_SAMPLE_DESC:
            pos += sizeof(DXGI_SAMPLE_DESC);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_NODE_MASK:
            pos += sizeof(D3D12_NODE_MASK);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_CACHED_PSO:
            pos += sizeof(D3D12_CACHED_PIPELINE_STATE);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_FLAGS:
            pos += sizeof(D3D12_PIPELINE_STATE_FLAGS);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_DEPTH_STENCIL1:
            pos += sizeof(D3D12_DEPTH_STENCIL_DESC1);
            break;
        case D3D12_PIPELINE_STATE_SUBOBJECT_TYPE_VIEW_INSTANCING:
            pos += sizeof(D3D12_VIEW_INSTANCING_DESC);
            break;
        default:
            spdlog::error("Unknown pipeline state subobject {}", type);
            pos += 0x100000000ULL;
        }
        pos += (0x08ULL - (pos & 0x07ULL)) & 0x07ULL;
    }

    HRESULT hr = create_pipeline_state_fn(device, pDesc, riid, ppPipelineState);
    if (pixelShaderPtr != nullptr) {
        delete *pixelShaderPtr;
        *pixelShaderPtr = origPixelShader;
        *pixelShaderSizePtr = origPixelShaderSize;
    }

    spdlog::info("  returns result = {}", hr);
    return hr;
}

HRESULT WINAPI D3D12Hook::create_pipeline_library(ID3D12Device4* device, const void* pLibraryBlob, SIZE_T BlobLength, REFIID riid, void** ppPipelineLibrary)
{
    spdlog::info("D3D12Hook::create_pipeline_library called with blob size={}", BlobLength);
    auto d3d12 = g_d3d12_hook;
    auto create_pipeline_library_fn = d3d12->m_create_pipeline_library_hook->get_original<decltype(D3D12Hook::create_pipeline_library)*>();

    // invalidate a cached library to force reloading of all shaders
    if (pLibraryBlob != nullptr && BlobLength != 0)
    {
        *ppPipelineLibrary = nullptr;
        return E_INVALIDARG;                // E_INVALIDARG if the blob is corrupted or unrecognized.
    }

    // forwarding for empty library creation
    return create_pipeline_library_fn(device, nullptr, 0, riid, ppPipelineLibrary);
}
