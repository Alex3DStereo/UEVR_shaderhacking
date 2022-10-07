// Helper header to easily instantiate a plugin
// and get some initial callbacks setup
// the user can inherit from the Plugin class
// and set uevr::g_plugin to their plugin instance
#pragma once

#include <windows.h>

#include "API.hpp"

namespace uevr {
class Plugin;

namespace detail {
    static inline ::uevr::Plugin* g_plugin{nullptr};
}

class Plugin {
public:
    Plugin() { detail::g_plugin = this; }

    virtual ~Plugin() = default;
    virtual void on_dllmain() {}
    virtual void on_initialize() {}
    virtual void on_present() {}
    virtual void on_device_reset() {}
    virtual bool on_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) { return true; }
    virtual void on_engine_tick(UEVR_UGameEngineHandle engine, float delta) {}
    virtual void on_slate_draw_window(UEVR_FSlateRHIRendererHandle renderer, UEVR_FViewportInfoHandle viewport_info) {}

protected:
};
}

extern "C" __declspec(dllexport) void uevr_plugin_required_version(UEVR_PluginVersion* version) {
    version->major = UEVR_PLUGIN_VERSION_MAJOR;
    version->minor = UEVR_PLUGIN_VERSION_MINOR;
    version->patch = UEVR_PLUGIN_VERSION_PATCH;
}

extern "C" __declspec(dllexport) bool uevr_plugin_initialize(const UEVR_PluginInitializeParam* param) {
    auto& api = uevr::API::initialize(param);
    uevr::detail::g_plugin->on_initialize();

    auto callbacks = param->callbacks;
    auto sdk_callbacks = param->sdk->callbacks;

    callbacks->on_device_reset([]() {
        uevr::detail::g_plugin->on_device_reset();
    });

    callbacks->on_present([]() {
        uevr::detail::g_plugin->on_present();
    });

    callbacks->on_message([](void* hwnd, unsigned int msg, unsigned long long wparam, long long lparam) {
        return uevr::detail::g_plugin->on_message((HWND)hwnd, msg, wparam, lparam);
    });

    sdk_callbacks->on_engine_tick([](UEVR_UGameEngineHandle engine, float delta) {
        uevr::detail::g_plugin->on_engine_tick(engine, delta);
    });

    sdk_callbacks->on_slate_draw_window_render_thread([](UEVR_FSlateRHIRendererHandle renderer, UEVR_FViewportInfoHandle viewport_info) {
        uevr::detail::g_plugin->on_slate_draw_window(renderer, viewport_info);
    });

    return true;
}

BOOL APIENTRY DllMain(HANDLE handle, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        uevr::detail::g_plugin->on_dllmain();
    }

    return TRUE;
}
