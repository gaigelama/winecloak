/* winecheck3.c — "is this a real, used machine?" surface (the APT-style checks). */
#define COBJMACROS
#include <windows.h>
#include <intrin.h>
#include <objbase.h>
#include <wbemidl.h>
#include <stdio.h>

int main(void){
    int r[4];
    __cpuid(r,1);
    int hv = (r[2]>>31)&1;
    printf("== anti-VM surface (want all 'real') ==\n");
    printf("  CPUID.1:ECX[31] hypervisor present = %d  %s\n", hv, hv?"<-- VM TELL":"(bare metal, good)");
    __cpuid(r,0x40000000);
    char vend[13]={0}; memcpy(vend,&r[1],4); memcpy(vend+4,&r[2],4); memcpy(vend+8,&r[3],4);
    int printable=1; for(int i=0;i<12;i++) if(vend[i] && (vend[i]<32||vend[i]>126)) printable=0;
    printf("  CPUID.40000000 hypervisor vendor   = \"%s\" %s\n", printable?vend:"", (printable&&vend[0])?"<-- VM TELL":"(none, good)");

    MEMORYSTATUSEX m; m.dwLength=sizeof m; GlobalMemoryStatusEx(&m);
    SYSTEM_INFO si; GetSystemInfo(&si);
    ULARGE_INTEGER disk; GetDiskFreeSpaceExA("C:\\",NULL,&disk,NULL);
    printf("\n== resource shape (sandboxes are tiny) ==\n");
    printf("  logical processors = %lu\n", si.dwNumberOfProcessors);
    printf("  physical RAM       = %.1f GB\n", m.ullTotalPhys/1073741824.0);
    printf("  C: total size      = %.1f GB\n", disk.QuadPart/1073741824.0);
    printf("  uptime             = %.1f min (GetTickCount64)\n", GetTickCount64()/60000.0);

    printf("\n== WMI 'real machine' surface (empty = Wine tell) ==\n");
    const char* q[][3] = {
      {"root\\cimv2","Win32_ComputerSystem","Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors"},
      {"root\\cimv2","Win32_BIOS","Manufacturer,SerialNumber,SMBIOSBIOSVersion"},
      {"root\\cimv2","Win32_Processor","Name,NumberOfCores,ProcessorId"},
      {"root\\cimv2","Win32_DiskDrive","Model,Size,SerialNumber"},
      {"root\\cimv2","Win32_PhysicalMemory","Capacity,Manufacturer,PartNumber"},
      {"root\\cimv2","Win32_VideoController","Name,AdapterRAM,DriverVersion"},
      {"root\\cimv2","Win32_NetworkAdapterConfiguration","MACAddress,IPAddress"},
      {"root\\cimv2","Win32_BaseBoard","Manufacturer,Product,SerialNumber"},
      {"root\\cimv2","Win32_Fan","DesiredSpeed,ActiveCooling"},
      {"root\\cimv2","Win32_TemperatureProbe","CurrentReading,Description"},
      {"root\\cimv2","Win32_PnPEntity","Name"},
      {"root\\cimv2","Win32_OperatingSystem","Caption,SerialNumber,InstallDate"},
      {"root\\wmi","MSAcpi_ThermalZoneTemperature","CurrentTemperature"},
      {0,0,0}
    };
    IWbemLocator* loc=NULL; IWbemServices* svc=NULL;
    CoInitializeEx(0,COINIT_MULTITHREADED);
    CoInitializeSecurity(0,-1,0,0,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,0,EOAC_NONE,0);
    if(CoCreateInstance(&CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,&IID_IWbemLocator,(void**)&loc)!=S_OK||!loc){
        printf("  (WbemLocator unavailable)\n"); return 0; }
    for(int i=0;q[i][0];i++){
        BSTR ns=SysAllocStringLen(0,256); MultiByteToWideChar(CP_ACP,0,q[i][0],-1,ns,256);
        svc=NULL;
        HRESULT hr=loc->lpVtbl->ConnectServer(loc,ns,0,0,0,0,0,0,&svc);
        if(hr!=S_OK||!svc){ printf("  %-34s : namespace %s unavailable\n",q[i][1],q[i][0]); SysFreeString(ns); continue; }
        CoSetProxyBlanket((IUnknown*)svc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,0,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,0,EOAC_NONE);
        char wql[128]; snprintf(wql,sizeof wql,"SELECT * FROM %s",q[i][1]);
        BSTR lang=SysAllocString(L"WQL"); BSTR query=SysAllocStringLen(0,256);
        MultiByteToWideChar(CP_ACP,0,wql,-1,query,256);
        IEnumWbemClassObject* en=NULL;
        hr=svc->lpVtbl->ExecQuery(svc,lang,query,WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,0,&en);
        int count=0; char first[256]="";
        if(hr==S_OK&&en){ IWbemClassObject* o=NULL; ULONG ret=0;
            while(en->lpVtbl->Next(en,2000,1,&o,&ret)==S_OK&&ret){
                if(count==0){ VARIANT v; VariantInit(&v);
                    // grab first requested prop for a sample value
                    char p0[64]; sscanf(q[i][2],"%63[^,]",p0);
                    BSTR pw=SysAllocStringLen(0,64); MultiByteToWideChar(CP_ACP,0,p0,-1,pw,64);
                    if(o->lpVtbl->Get(o,pw,0,&v,0,0)==S_OK && v.vt==VT_BSTR && v.bstrVal)
                        WideCharToMultiByte(CP_ACP,0,v.bstrVal,-1,first,sizeof first,0,0);
                    else if(v.vt==VT_I4) snprintf(first,sizeof first,"%d",v.lVal);
                    SysFreeString(pw); VariantClear(&v);
                }
                count++; o->lpVtbl->Release(o);
            }
            en->lpVtbl->Release(en);
        }
        printf("  %-34s : %d instance(s)%s%s %s\n",q[i][1],count,
               first[0]?"  first=":"",first, count==0?"<-- EMPTY (tell)":"");
        SysFreeString(lang);SysFreeString(query);SysFreeString(ns);
        svc->lpVtbl->Release(svc);
    }
    return 0;
}
