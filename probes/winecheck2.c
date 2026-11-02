/* winecheck2.c — deep Wine-detection probe. Build with mingw-w64 (64-bit). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int hits = 0;
static void flag(const char* s){ printf("   <-- TELL: %s\n", s); hits++; }

static int has_ci(const char* hay, int n, const char* needle){
    int m=strlen(needle);
    for(int i=0;i+m<=n;i++){ int k=0; for(;k<m;k++){ char a=hay[i+k]|32,b=needle[k]|32; if(a!=b)break;} if(k==m)return 1;}
    return 0;
}

static void check_export(const char* mod, const char* name){
    HMODULE h=GetModuleHandleA(mod); if(!h) h=LoadLibraryA(mod);
    FARPROC p=h?GetProcAddress(h,name):NULL;
    printf("  %-10s!%-26s = %p%s\n", mod, name, (void*)p, p?"":"  ");
    if(p){ char b[128]; snprintf(b,sizeof b,"%s exports %s",mod,name); flag(b);}
}

static void regval(HKEY root,const char* path,const char* val){
    HKEY k; if(RegOpenKeyExA(root,path,0,KEY_READ|KEY_WOW64_64KEY,&k)) { printf("  [%s\\%s] (open failed)\n",path,val?val:""); return;}
    char buf[1024]; DWORD sz=sizeof buf, type=0;
    LONG r=RegQueryValueExA(k,val,0,&type,(BYTE*)buf,&sz);
    if(!r){
        // normalize REG_MULTI_SZ nulls to spaces for printing
        if(type==REG_MULTI_SZ) for(DWORD i=0;i+1<sz;i++) if(!buf[i]) buf[i]=' ';
        printf("  %-42s = \"%s\"\n", val, buf);
        const char* bad[]={"wine","qemu","virtualbox","vmware","innotek","bochs","0xabcdef",0};
        for(int i=0;bad[i];i++) if(has_ci(buf,(int)sz,bad[i])){ char m[160]; snprintf(m,sizeof m,"%s contains \"%s\"",val,bad[i]); flag(m);}
    } else printf("  %-42s (not set)\n", val);
    RegCloseKey(k);
}

int main(void){
    printf("== ntdll / kernel32 wine_* exports ==\n");
    const char* nt[]={"wine_get_version","wine_get_build_id","wine_get_host_version",
                      "wine_server_call","wine_server_fd_to_handle","wine_unix_to_nt_file_name",
                      "wine_nt_to_unix_file_name","__wine_dbg_write",0};
    for(int i=0;nt[i];i++) check_export("ntdll",nt[i]);
    check_export("kernel32","wine_get_unix_file_name");
    check_export("kernel32","wine_get_dos_file_name");

    printf("\n== core DLL load health (should all be non-NULL; NULL = I broke something) ==\n");
    const char* core[]={"shell32.dll","user32.dll","gdi32.dll","advapi32.dll","ole32.dll","ws2_32.dll",0};
    for(int i=0;core[i];i++){ HMODULE h=LoadLibraryA(core[i]); printf("  %-14s = %s\n",core[i],h?"ok":"FAILED TO LOAD"); if(!h){char b[64];snprintf(b,sizeof b,"%s failed to load",core[i]);flag(b);} }

    printf("\n== SMBIOS / DMI (registry mirror) ==\n");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\BIOS","SystemManufacturer");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\BIOS","SystemProductName");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\BIOS","BIOSVendor");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\BIOS","BIOSVersion");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\BIOS","BaseBoardManufacturer");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System","SystemBiosVersion");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System","VideoBiosVersion");
    regval(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0","ProcessorNameString");

    printf("\n== raw SMBIOS table strings (GetSystemFirmwareTable 'RSMB') ==\n");
    UINT sz=GetSystemFirmwareTable('RSMB',0,NULL,0);
    if(sz){ BYTE* b=(BYTE*)malloc(sz); UINT got=GetSystemFirmwareTable('RSMB',0,b,sz);
        const char* bad[]={"wine","qemu","virtualbox","vmware","innotek","bochs",0};
        for(int i=0;bad[i];i++) if(has_ci((char*)b,(int)got,bad[i])){char m[64];snprintf(m,sizeof m,"SMBIOS contains \"%s\"",bad[i]);flag(m);}
        // print printable runs (like `strings`) so we see manufacturer/product
        char run[256]; int rl=0; printf("  strings:");
        for(UINT i=0;i<got;i++){ char c=b[i]; if(c>=32&&c<127&&rl<255) run[rl++]=c; else { if(rl>=4){run[rl]=0; printf(" [%s]",run);} rl=0;} }
        printf("\n"); free(b);
    } else printf("  (GetSystemFirmwareTable returned 0)\n");

    printf("\n== leftover wine files in system32 ==\n");
    const char* wf[]={"wineboot.exe","winedevice.exe","winecfg.exe","winemenubuilder.exe",
                      "winex11.drv","winevulkan.dll","wined3d.dll","start.exe","explorer.exe",0};
    for(int i=0;wf[i];i++){ char p[160]; snprintf(p,sizeof p,"C:\\windows\\system32\\%s",wf[i]);
        DWORD a=GetFileAttributesA(p); printf("  %-20s = %s\n",wf[i],a!=INVALID_FILE_ATTRIBUTES?"present":"absent");
        if(a!=INVALID_FILE_ATTRIBUTES && (strncmp(wf[i],"wine",4)==0)){char m[64];snprintf(m,sizeof m,"%s present",wf[i]);flag(m);} }

    printf("\n  TOTAL TELLS: %d\n", hits);
    return hits;
}
