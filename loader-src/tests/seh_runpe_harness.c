// Direct, benign RunPE source harness: compile the actual inmem_pe.c, fake only OS services.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wire_abi_contract.h"
int ansi2unicode(PDONUT_INSTANCE inst, CHAR input[], WCHAR output[DONUT_MAX_NAME]);
#include "../loader/inmem_pe.c"

static DONUT_INSTANCE instance;
static PDONUT_MODULE module;
static BYTE *mapped;
static int maps, unmaps, adds, deletes, entries, tls_calls, errors;
static int add_result, delete_result, resolver_missing, delete_missing;
static int thread_mode, wait_calls, thread_closes, remap_mode, remap_base_preserved;
static DWORD wait_result;
static ULONGLONG original_base;
static char events[32];
static int event_count;
static const ULONGLONG hash_sentinel = 0x123456789abcdef0ULL;
static RUNTIME_FUNCTION *expected_table;

static void event(char code) { if (event_count < sizeof(events)-1) { events[event_count++] = code; events[event_count] = 0; } }
static void check(int value, const char *message) { if (!value) { fprintf(stderr, "FAIL %s: %s\n", events, message); errors++; } }
static HANDLE WINAPI current_process(void) { return GetCurrentProcess(); }
static HMODULE WINAPI get_module(LPCSTR name) {
    if (name == NULL) return GetModuleHandleA(NULL);
    return strcmp(name, "ntdll.dll") == 0 ? (HMODULE)0x1234 : NULL;
}
static BOOLEAN WINAPI fake_delete(PRUNTIME_FUNCTION table) {
    deletes++; event('D'); check(table == expected_table, "Delete table address"); return delete_result;
}
static BOOLEAN WINAPI fake_add(PRUNTIME_FUNCTION table, DWORD count, DWORD64 base) {
    adds++; event('A'); check(table == expected_table, "Add table address");
    check(count == 2, "Add entry count"); check(base == (DWORD64)mapped, "Add mapped base");
    return add_result;
}
// Avoid a real ntdll registration. GetProcAddress returns this stub, not the imported API.
static FARPROC WINAPI resolve_name(HMODULE lib, LPCSTR name) {
    if (delete_missing || lib != (HMODULE)0x1234 || strcmp(name,"RtlDeleteFunctionTable") != 0) return NULL;
    return (FARPROC)fake_delete;
}
LPVOID xGetProcAddressByHash(PDONUT_INSTANCE inst, ULONGLONG hash, ULONGLONG iv) {
    (void)inst; (void)iv;
    check(hash == hash_sentinel, "lazy slot hash");
    return resolver_missing ? NULL : (LPVOID)fake_add;
}
LPVOID xGetLibAddress(PDONUT_INSTANCE inst, PCHAR name) { (void)inst; (void)name; return NULL; }
LPVOID xGetProcAddress(PDONUT_INSTANCE inst, LPVOID base, PCHAR name, DWORD ordinal) { (void)inst;(void)base;(void)name;(void)ordinal;return NULL; }
void *Memset(void *p,int v,unsigned int n) { return memset(p,v,n); }
void *Memcpy(void *d,const void *s,unsigned int n) { return memcpy(d,s,n); }
int _strcmp(const char *a,const char *b) { return strcmp(a,b); }
int ansi2unicode(PDONUT_INSTANCE inst, CHAR input[], WCHAR output[DONUT_MAX_NAME]) { (void)inst;(void)input;(void)output;return 0; }
static NTSTATUS WINAPI create_section(PHANDLE handle, ACCESS_MASK access, PVOID attr, PLARGE_INTEGER size, ULONG protect, ULONG alloc, HANDLE file) {
    (void)access;(void)attr;(void)size;(void)protect;(void)alloc;(void)file; *handle=(HANDLE)0x4321;return 0;
}
static NTSTATUS WINAPI map_section(HANDLE handle,HANDLE process,PVOID *base,ULONG_PTR zero,SIZE_T commit,PLARGE_INTEGER offset,PSIZE_T size,SECTION_INHERIT inherit,ULONG alloc,ULONG protect) {
    (void)handle;(void)process;(void)zero;(void)commit;(void)offset;(void)inherit;(void)alloc;(void)protect;
    maps++; if (!mapped) mapped = VirtualAlloc(NULL,0x6000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    check(mapped != NULL,"mapped view allocation");
    expected_table=(RUNTIME_FUNCTION*)(mapped+0x1100);
    if(maps==2 && remap_mode) {
        ULONGLONG relocated = *(ULONGLONG *)(mapped+0x3400);
        check(*base==mapped,"remap must request first base");
        check(relocated == (ULONGLONG)mapped + 0x1234,"forced relocation survived remap");
        remap_base_preserved = (*base==mapped && relocated == (ULONGLONG)mapped + 0x1234);
    }
    if(maps==1) {
        // Absolute TLS pointers must name the eventual mapped image.
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(module->data + 0x400 + (0x3200-0x1000));
        tls->AddressOfCallBacks = (ULONGLONG)(mapped+0x3300);
    }
    *base=mapped;*size=0x6000;return 0;
}
static NTSTATUS WINAPI unmap_section(HANDLE process,PVOID base) { (void)process;check(base==mapped,"unmap mapped base"); unmaps++; event('U');return 0; }
static BOOL WINAPI protect(LPVOID address,SIZE_T size,DWORD flags,PDWORD old) { (void)address;(void)size;(void)flags;*old=PAGE_READWRITE;return TRUE; }
static LPVOID WINAPI alloc(LPVOID address,SIZE_T size,DWORD type,DWORD protect_value) {return VirtualAlloc(address,size,type,protect_value);}
static BOOL WINAPI release(LPVOID address,SIZE_T size,DWORD type) {(void)size;(void)type;return VirtualFree(address,0,MEM_RELEASE);}
static BOOL WINAPI close_handle(HANDLE h) {
    if (h==(HANDLE)0x4321) event('C');
    else if (h==(HANDLE)0x123456) {thread_closes++;event('H');}
    else check(0,"unknown handle");
    return TRUE;
}
static HANDLE WINAPI create_thread(LPSECURITY_ATTRIBUTES attrs, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID arg, DWORD flags, LPDWORD id) {
    (void)attrs;(void)stack;(void)start;(void)arg;(void)flags;(void)id;
    event('R');return (HANDLE)0x123456;
}
static DWORD WINAPI wait_thread(HANDLE h, DWORD timeout) {
    check(h==(HANDLE)0x123456 && timeout==INFINITE,"wait target");
    wait_calls++;event('W');return wait_result;
}
static BOOL WINAPI entry(HINSTANCE h,DWORD reason,LPVOID reserved) {(void)h;(void)reason;(void)reserved;entries++;event('E');return TRUE;}
static void WINAPI tls_callback(PVOID h,DWORD reason,PVOID reserved) {(void)h;(void)reason;(void)reserved;tls_calls++;event('T');}
static void jump_to(BYTE *dest, void *fn) {
    dest[0]=0xff;dest[1]=0x25; memset(dest+2,0,4);memcpy(dest+6,&fn,8);
}
static void setup(int dll, int with_table) {
    IMAGE_DOS_HEADER *dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER section;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK *callback;
    RUNTIME_FUNCTION *table;
    memset(&instance,0,sizeof(instance));
    module = (PDONUT_MODULE)calloc(1,sizeof(DONUT_MODULE)+0x4000);
    check(module!=NULL,"source allocation");
    module->type=dll?DONUT_MODULE_DLL:DONUT_MODULE_EXE;
    dos=(IMAGE_DOS_HEADER*)module->data;dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=0x80;
    nt=(PIMAGE_NT_HEADERS)(module->data+0x80);
    nt->Signature=IMAGE_NT_SIGNATURE;nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections=1;nt->FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.SizeOfImage=0x5000;nt->OptionalHeader.SizeOfHeaders=0x400;
    nt->OptionalHeader.BaseOfCode=0x1000;nt->OptionalHeader.AddressOfEntryPoint=0x2000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=with_table?0x1100:0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size=with_table?2*sizeof(RUNTIME_FUNCTION):0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress=0x3200;
    section=IMAGE_FIRST_SECTION(nt);section->VirtualAddress=0x1000;section->PointerToRawData=0x400;
    section->SizeOfRawData=0x3000;section->Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;
    jump_to(module->data+0x400+0x1000,(void*)entry);
    table=(RUNTIME_FUNCTION*)(module->data+0x400+0x100);table[0].BeginAddress=0x2000;
    table[0].EndAddress=0x2100;table[0].UnwindData=0x3100;
    table[1].BeginAddress=0x2200;table[1].EndAddress=0x2300;table[1].UnwindData=0x3100;
    tls=(PIMAGE_TLS_DIRECTORY)(module->data+0x400+0x2200);
    callback=(PIMAGE_TLS_CALLBACK*)(module->data+0x400+0x2300);callback[0]=tls_callback;
    (void)tls;
    instance.api.hash[63]=hash_sentinel;
    instance.api.GetModuleHandle=get_module;instance.api.GetProcAddress=resolve_name;
    instance.api.GetCurrentProcess=current_process;
    instance.api.NtCreateSection=create_section;instance.api.NtMapViewOfSection=map_section;
    instance.api.NtUnmapViewOfSection=unmap_section;instance.api.VirtualProtect=protect;
    instance.api.VirtualAlloc=alloc;instance.api.VirtualFree=release;
    instance.api.CloseHandle=close_handle;
    instance.api.CreateThread=create_thread;instance.api.WaitForSingleObject=wait_thread;
    maps=unmaps=adds=deletes=entries=tls_calls=0;event_count=0;events[0]=0;
    thread_mode=wait_calls=thread_closes=remap_mode=remap_base_preserved=0;
    wait_result=WAIT_OBJECT_0;original_base=0;
    mapped=NULL;expected_table=NULL;
    add_result=delete_result=TRUE;resolver_missing=delete_missing=0;
}
static PIMAGE_NT_HEADERS input_nt(void) {return (PIMAGE_NT_HEADERS)(module->data+0x80);}
static RUNTIME_FUNCTION *input_table(void) {return (RUNTIME_FUNCTION*)(module->data+0x400+0x100);}
static void execute(const char *test,const char *want,int want_add,int want_delete,int want_entry) {
    // First-map allocation occurs during RunPE; expected_table is set by map_section.
    RunPE(&instance,module);
    printf("%s: events=%s maps=%d unmaps=%d add=%d delete=%d entry=%d tls=%d\n",test,events,maps,unmaps,adds,deletes,entries,tls_calls);
    check(strcmp(events,want)==0,"event order");
    check(adds==want_add && deletes==want_delete,"Add/Delete calls");
    check(entries==want_entry && tls_calls==(thread_mode?1:want_entry),"entry/TLS calls");
    check(maps==2,"final remap path");
    if (thread_mode) check(wait_calls==1 && thread_closes==1,"wait/close exactly once");
    if (remap_mode) check(remap_base_preserved,"remap final base and pointer");
    if(mapped) VirtualFree(mapped,0,MEM_RELEASE);
    free(module);
}
int main(void) {
    setup(0,1);execute("EXE normal","UATEDUC",1,1,1);
    setup(0,1);module->thread=1;thread_mode=1;execute("thread completed","UATRWHDUC",1,1,0);
    setup(0,1);module->thread=1;thread_mode=1;wait_result=WAIT_FAILED;execute("thread WAIT_FAILED retains registration","UATRWHC",1,0,0);
    setup(0,1);module->thread=1;thread_mode=1;wait_result=WAIT_TIMEOUT;execute("thread non-object retains registration","UATRWHC",1,0,0);
    setup(0,1);remap_mode=1;original_base=0x10000000;
    input_nt()->OptionalHeader.ImageBase=original_base;
    input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=0x3500;
    input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=12;
    { IMAGE_BASE_RELOCATION *rel=(IMAGE_BASE_RELOCATION *)(module->data+0x400+0x2500);
      WORD *fix=(WORD *)(rel+1);
      rel->VirtualAddress=0x3000;rel->SizeOfBlock=12;
      fix[0]=(IMAGE_REL_BASED_DIR64<<12)|0x400;fix[1]=0;
      *(ULONGLONG *)(module->data+0x400+0x2400)=original_base+0x1234;
    }
    execute("forced relocation/remap","UATEDUC",1,1,1);
    setup(1,1);execute("DLL normal","UATEDUC",1,1,1);
    setup(0,0);execute("absent 0/0","UTEUC",0,0,1);
    setup(0,1);add_result=FALSE;execute("Add false","UAUC",1,0,0);
    setup(0,1);delete_result=FALSE;execute("Delete false retains view","UATEDC",1,1,1);
    setup(0,1);resolver_missing=TRUE;execute("Add resolver missing","UUC",0,0,0);
    setup(0,1);delete_missing=TRUE;execute("Delete resolver missing","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.NumberOfRvaAndSizes=3;execute("undeclared directory","UUC",0,0,0);
    setup(0,1);input_nt()->FileHeader.SizeOfOptionalHeader=offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);execute("short optional header","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size=0;execute("one-zero size","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0;execute("one-zero rva","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0x1101;execute("misaligned","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size=13;execute("partial table","UUC",0,0,0);
    setup(0,1);input_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0x4ff0;execute("out of image","UUC",0,0,0);
    setup(0,1);input_table()[0].BeginAddress=input_table()[0].EndAddress;execute("empty entry","UUC",0,0,0);
    setup(0,1);input_table()[1].BeginAddress=0x2001;execute("unordered entries","UUC",0,0,0);
    setup(0,1);input_table()[1].EndAddress=0x5001;execute("end beyond image","UUC",0,0,0);
    setup(0,1);input_table()[0].UnwindData=0x5000;execute("unwind beyond image","UUC",0,0,0);
    return errors?1:0;
}
