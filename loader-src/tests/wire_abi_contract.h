// Fixed v1.1 wire contract: do not derive these from the Go importer or C field order.
#ifndef SEH_WIRE_ABI_CONTRACT_H
#define SEH_WIRE_ABI_CONTRACT_H
#include <stddef.h>
#include "../loader/loader.h"
#define WIRE_ASSERT(name, condition) typedef char wire_assert_##name[(condition) ? 1 : -1]
WIRE_ASSERT(pointer_width, sizeof(void *) == 8);
WIRE_ASSERT(iv_offset, offsetof(DONUT_INSTANCE, iv) == 40);
WIRE_ASSERT(hash_offset, offsetof(DONUT_INSTANCE, api.hash) == 48);
WIRE_ASSERT(addr_offset, offsetof(DONUT_INSTANCE, api.addr) == 48);
WIRE_ASSERT(first_function, offsetof(DONUT_INSTANCE, api.LoadLibraryA) == 48);
WIRE_ASSERT(wininet_query_slot40, offsetof(DONUT_INSTANCE, api.InternetQueryDataAvailable) == 48 + 40 * 8);
WIRE_ASSERT(wininet_close_slot41, offsetof(DONUT_INSTANCE, api.InternetCloseHandle) == 48 + 41 * 8);
WIRE_ASSERT(last_eager_slot62, offsetof(DONUT_INSTANCE, api.NtUnmapViewOfSection) == 48 + 62 * 8);
WIRE_ASSERT(lazy_slot63, offsetof(DONUT_INSTANCE, api.RtlAddFunctionTable) == 48 + 63 * 8);
WIRE_ASSERT(api_union_size, sizeof(((DONUT_INSTANCE *)0)->api) == 512);
WIRE_ASSERT(exit_offset, offsetof(DONUT_INSTANCE, exit_opt) == 560);
WIRE_ASSERT(entropy_offset, offsetof(DONUT_INSTANCE, entropy) == 564);
WIRE_ASSERT(oep_offset, offsetof(DONUT_INSTANCE, oep) == 568);
WIRE_ASSERT(api_count_offset, offsetof(DONUT_INSTANCE, api_cnt) == 572);
WIRE_ASSERT(dll_names_offset, offsetof(DONUT_INSTANCE, dll_names) == 576);
WIRE_ASSERT(module_offset, offsetof(DONUT_INSTANCE, module) == 3424);
#endif
