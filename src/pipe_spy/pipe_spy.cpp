#include <set>

#include <koalabox/globals.hpp>
#include <koalabox/hook.hpp>
#include <koalabox/logger.hpp>
#include <koalabox/paths.hpp>
#include <koalabox/str.hpp>
#include <koalabox/util.hpp>
#include <koalabox/win.hpp>

#include "build_config.h"

#include "pipe_spy.hpp"

namespace {
    namespace kb = koalabox;

#define GET_ORIGINAL_FUNCTION(FUNC) \
    hook_delay(#FUNC); \
    static const auto _##FUNC = KB_HOOK_GET_HOOKED_FN(FUNC);

    std::set<HANDLE> read_pipes; // NOLINT(cert-err58-cpp)
    std::set<HANDLE> write_pipes; // NOLINT(cert-err58-cpp)

    void hook_delay(LPCSTR function) {
        // Sometimes the hooked function begins execution before
        // hooking has been fully completed yet, so we have to wait a little.
        while(not kb::hook::is_hooked(function)) {
            LOG_DEBUG("{} -> Sleeping 10 ms", function);
            Sleep(10);
        }
    }

    BOOL WINAPI ReadFile_Hooked(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ) {
        GET_ORIGINAL_FUNCTION(ReadFile);

        const auto result = _ReadFile(
            hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            lpOverlapped
        );

        if(read_pipes.contains(hFile)) {
            const auto string_buffer = std::string{
                static_cast<LPCSTR>(lpBuffer),
                nNumberOfBytesToRead
            };

            LOG_INFO(
                "{} -> handle: {}, size: {}, buffer:\n{}",
                __func__,
                hFile,
                nNumberOfBytesToRead,
                string_buffer
            );
        }

        if(result == FALSE) {
            LOG_WARN("Failed to read from file {}", (void*) hFile);
        }

        return result;
    }

    BOOL WINAPI WriteFile_Hooked(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ) {
        GET_ORIGINAL_FUNCTION(WriteFile);

        if(write_pipes.contains(hFile)) {
            const auto string_buffer = std::string{(LPCSTR) lpBuffer, nNumberOfBytesToWrite};
            LOG_DEBUG(
                "{} -> handle: {}, size: {}, buffer:\n{}",
                __func__,
                hFile,
                nNumberOfBytesToWrite,
                string_buffer
            );
        }

        const auto result = _WriteFile(
            hFile,
            lpBuffer,
            nNumberOfBytesToWrite,
            lpNumberOfBytesWritten,
            lpOverlapped
        );

        if(result == FALSE) {
            LOG_WARN("Failed to write to file");
        }

        return result;
    }

    BOOL DuplicateHandle_Hooked(
        HANDLE hSourceProcessHandle,
        HANDLE hSourceHandle,
        HANDLE hTargetProcessHandle,
        LPHANDLE lpTargetHandle,
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwOptions
    ) {
        GET_ORIGINAL_FUNCTION(DuplicateHandle);

        const auto result = _DuplicateHandle(
            hSourceProcessHandle,
            hSourceHandle,
            hTargetProcessHandle,
            lpTargetHandle,
            dwDesiredAccess,
            bInheritHandle,
            dwOptions
        );

        LOG_DEBUG(
            "{} -> result: {}, source: {}, target: {}",
            __func__,
            result,
            hSourceHandle,
            *lpTargetHandle
        );

        if(result && hSourceHandle && lpTargetHandle) {
            if(read_pipes.contains(hSourceHandle)) {
                LOG_INFO("{} -> Duplication of read pipe detected", __func__);
                read_pipes.insert(*lpTargetHandle);
            }

            if(write_pipes.contains(hSourceHandle)) {
                LOG_INFO("{} -> Duplication of write pipe detected", __func__);
                write_pipes.insert(*lpTargetHandle);
            }
        }

        return result;
    }

    BOOL WINAPI CreatePipe_Hooked(
        PHANDLE hReadPipe,
        PHANDLE hWritePipe,
        LPSECURITY_ATTRIBUTES lpPipeAttributes,
        DWORD nSize
    ) {
        GET_ORIGINAL_FUNCTION(CreatePipe);

        const auto result = _CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);

        LOG_INFO(
            "{} -> result: {}, read: {}, write: {}, size: {}",
            __func__,
            result,
            *hReadPipe,
            *hWritePipe,
            nSize
        );

        if(result && hReadPipe && hWritePipe) {
            read_pipes.insert(*hReadPipe);
            write_pipes.insert(*hWritePipe);
        }

        return result;
    }

    HANDLE CreateNamedPipeA_Hooked(
        LPCSTR lpName,
        DWORD dwOpenMode,
        DWORD dwPipeMode,
        DWORD nMaxInstances,
        DWORD nOutBufferSize,
        DWORD nInBufferSize,
        DWORD nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ) {
        GET_ORIGINAL_FUNCTION(CreateNamedPipeA);

        LOG_INFO("{} -> name: {}", __func__, lpName);

        return _CreateNamedPipeA(
            lpName,
            dwOpenMode,
            dwPipeMode,
            nMaxInstances,
            nOutBufferSize,
            nInBufferSize,
            nDefaultTimeOut,
            lpSecurityAttributes
        );
    }

    HANDLE CreateNamedPipeW_Hooked(
        LPCWSTR lpName,
        DWORD dwOpenMode,
        DWORD dwPipeMode,
        DWORD nMaxInstances,
        DWORD nOutBufferSize,
        DWORD nInBufferSize,
        DWORD nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ) {
        GET_ORIGINAL_FUNCTION(CreateNamedPipeW);

        LOG_INFO("{} -> name: {}", __func__, kb::str::to_str(lpName));

        return _CreateNamedPipeW(
            lpName,
            dwOpenMode,
            dwPipeMode,
            nMaxInstances,
            nOutBufferSize,
            nInBufferSize,
            nDefaultTimeOut,
            lpSecurityAttributes
        );
    }
}

namespace pipe_spy {
    void init(const HMODULE handle) {
        try {
            kb::globals::init_globals(handle, PROJECT_NAME);
            kb::logger::init_file_logger(kb::paths::get_log_path());

            LOG_INFO("{} v{}", PROJECT_NAME, PROJECT_VERSION);

            auto* const kernel_module = kb::win::get_module_handle("Kernel32");

#define HOOK(FUNC) koalabox::hook::detour(kernel_module, #FUNC, reinterpret_cast<uintptr_t>(FUNC##_Hooked))

            // HOOK(DuplicateHandle) // TODO: Fix it!
            HOOK(CreatePipe);
            HOOK(ReadFile);
            HOOK(WriteFile);
            HOOK(CreateNamedPipeA);
            HOOK(CreateNamedPipeW);
        } catch(const std::exception& e) {
            kb::util::panic(std::format("Initialization error: {}", e.what()));
        }
    }

    void shutdown() {
        kb::logger::shutdown();
    }
}
