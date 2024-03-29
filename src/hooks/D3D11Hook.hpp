#pragma once

#include <functional>
#include <unordered_set> // :alex:

#include <d3d11.h>
#include <dxgi.h>
#include <wrl.h>

#include "utility/PointerHook.hpp"

class D3D11Hook {
public:
    typedef std::function<void(D3D11Hook&)> OnPresentFn;
    typedef std::function<void(D3D11Hook&, uint32_t w, uint32_t h)> OnResizeBuffersFn;

    D3D11Hook() = default;
    virtual ~D3D11Hook();

	bool is_hooked() {
		return m_hooked;
	}

    bool is_inside_present() const {
        return m_inside_present;
    }

    void ignore_next_present() {
        m_ignore_next_present = true;
    }

    void set_next_present_interval(uint32_t interval) {
        m_next_present_interval = interval;
    }

    bool hook();
    bool unhook();

    void on_present(OnPresentFn fn) { m_on_present = fn; }
    void on_post_present(OnPresentFn fn) { m_on_post_present = fn; }
    void on_resize_buffers(OnResizeBuffersFn fn) { m_on_resize_buffers = fn; }

    ID3D11Device* get_device() { return m_device; }
    IDXGISwapChain* get_swap_chain() { return m_swap_chain; } // The "active" swap chain.
    auto get_swapchain_0() { return m_swapchain_0; }
    auto get_swapchain_1() { return m_swapchain_1; }
    auto& get_last_depthstencil_used() { return m_last_depthstencil_used; }

protected:
    template<typename T> using ComPtr = Microsoft::WRL::ComPtr<T>;

    ID3D11Device* m_device{ nullptr };
    IDXGISwapChain* m_swap_chain{ nullptr };
    IDXGISwapChain* m_swapchain_0{};
    IDXGISwapChain* m_swapchain_1{};
    bool m_hooked{ false };
    bool m_inside_present{false};
    bool m_ignore_next_present{false};

    std::optional<uint32_t> m_next_present_interval{};

    std::unique_ptr<PointerHook> m_present_hook{};
    std::unique_ptr<PointerHook> m_resize_buffers_hook{};
    std::unique_ptr<PointerHook> m_set_render_targets_hook{};
    static std::unique_ptr<PointerHook> m_create_pixel_shader_hook; // :alex:
    OnPresentFn m_on_present{ nullptr };
    OnPresentFn m_on_post_present{ nullptr };
    OnResizeBuffersFn m_on_resize_buffers{ nullptr };
    ComPtr<ID3D11Texture2D> m_last_depthstencil_used{};

    // :alex:
    static std::unordered_set<uint64_t> m_dumped_shaders;

    static HRESULT WINAPI present(IDXGISwapChain* swap_chain, UINT sync_interval, UINT flags);
    static HRESULT WINAPI resize_buffers(IDXGISwapChain* swap_chain, UINT buffer_count, UINT width, UINT height, DXGI_FORMAT new_format, UINT swap_chain_flags);
    static void WINAPI set_render_targets(ID3D11DeviceContext* context, UINT num_views, ID3D11RenderTargetView* const* rtvs, ID3D11DepthStencilView* dsv);
    static HRESULT WINAPI create_pixel_shader(ID3D11Device* device, const void* pShaderBytecode, uint64_t BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader); // :alex:
};
