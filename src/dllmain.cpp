#include "pipe_spy/pipe_spy.hpp"

#include "linker_exports_for_iphlpapi.h"

EXTERN_C [[maybe_unused]] BOOL WINAPI
DllMain(const HMODULE handle, const DWORD reason, LPVOID) {
    if(reason == DLL_PROCESS_ATTACH) {
        pipe_spy::init(handle);
    } else if(reason == DLL_PROCESS_DETACH) {
        pipe_spy::shutdown();
    }

    return TRUE;
}
