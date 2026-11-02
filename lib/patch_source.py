#!/usr/bin/env python3
r"""Apply wine-cloak's SOURCE changes to a Wine tree by STRING ANCHORS (robust across
upstream/staging/GE forks, unlike a context diff). Edits two files:

  dlls/wbemprox/builtin.c   realistic disk model + Win32_Fan / Win32_TemperatureProbe /
                            MSAcpi_ThermalZoneTemperature classes
  dlls/ntdll/unix/system.c  ACPI firmware-table provider (serves host tables) + SKU sanitizer

Usage: patch_source.py <wine-src-root> [--acpi-dir <cache>]
The ACPI provider reads tables from <cache> first (populate it with `wine-cloak stage-acpi`),
falling back to /sys/firmware/acpi/tables.
"""
import sys, argparse

def must_replace(t, old, new, what, n=1):
    if t.count(old) < n:
        sys.exit(f"anchor not found ({what}): {old[:60]!r}")
    return t.replace(old, new, n)

def patch_builtin(path):
    t = open(path).read(); o = t
    if "col_thermalzone" in t:
        print("  builtin.c already patched"); return
    t = t.replace('L"Wine Disk Drive"', 'L"Samsung SSD 990 PRO"')
    t = t.replace('L"IDE\\\\Disk\\\\VEN_WINE"', 'L"IDE\\\\Disk\\\\VEN_SAMSUNG"')
    t = t.replace('L"Wine disk"', 'L"Samsung SSD 990 PRO"')
    defs = r'''
static const struct column col_thermalzone[] =
{
    { L"CriticalTripPoint",  CIM_UINT32 },
    { L"CurrentTemperature", CIM_UINT32 },
    { L"InstanceName",       CIM_STRING|COL_FLAG_KEY },
};
struct record_thermalzone { UINT32 criticaltrippoint; UINT32 currenttemperature; const WCHAR *instancename; };
static const struct record_thermalzone data_thermalzone[] = { { 3732, 3132, L"ACPI\\ThermalZone\\TZ00_0" } };

static const struct column col_fan[] =
{
    { L"ActiveCooling", CIM_BOOLEAN },
    { L"DesiredSpeed",  CIM_UINT64 },
    { L"DeviceID",      CIM_STRING|COL_FLAG_KEY },
    { L"Name",          CIM_STRING },
    { L"Status",        CIM_STRING },
};
struct record_fan { int activecooling; UINT64 desiredspeed; const WCHAR *device_id; const WCHAR *name; const WCHAR *status; };
static const struct record_fan data_fan[] = { { -1, 0, L"Fan 0", L"CPU Cooling Fan", L"OK" } };

static const struct column col_tempprobe[] =
{
    { L"CurrentReading", CIM_SINT32 },
    { L"Description",    CIM_STRING },
    { L"DeviceID",       CIM_STRING|COL_FLAG_KEY },
    { L"Name",           CIM_STRING },
    { L"Status",         CIM_STRING },
};
struct record_tempprobe { int currentreading; const WCHAR *description; const WCHAR *device_id; const WCHAR *name; const WCHAR *status; };
static const struct record_tempprobe data_tempprobe[] = { { 3132, L"CPU Thermal Probe", L"Temperature Probe 0", L"CPU Temperature", L"OK" } };

'''
    cimv2 = "static struct table cimv2_builtin_classes[] =\n{\n"
    t = must_replace(t, cimv2, defs + cimv2 +
                     '    { L"Win32_Fan", C(col_fan), D(data_fan) },\n'
                     '    { L"Win32_TemperatureProbe", C(col_tempprobe), D(data_tempprobe) },\n',
                     "cimv2 table")
    wmi = '    { L"MSSMBios_RawSMBiosTables", C(col_rawsmbiostables), 0, 0, NULL, fill_rawbiosdata },\n'
    t = must_replace(t, wmi, wmi + '    { L"MSAcpi_ThermalZoneTemperature", C(col_thermalzone), D(data_thermalzone) },\n',
                     "wmi table")
    open(path, "w").write(t); print("  builtin.c patched" if t != o else "  builtin.c unchanged")

def patch_system(path, acpi_dir):
    t = open(path).read(); o = t
    if "acpi_tables_dir" not in t:
        helper = ('static const char *acpi_tables_dir(void)\n{\n'
                  f'    static const char cache[] = "{acpi_dir}";\n'
                  '    if (access( cache, X_OK ) == 0) return cache;\n'
                  '    return "/sys/firmware/acpi/tables";\n}\n\n'
                  'static NTSTATUS enum_firmware_info(')
        t = must_replace(t, "static NTSTATUS enum_firmware_info(", helper, "enum_firmware_info")
        enum_anchor = "        *(UINT *)sfti->TableBuffer = 0;\n        return STATUS_SUCCESS;\n"
        enum_case = enum_anchor + r'''
    case ACPI:
    {
        DIR *d = opendir( acpi_tables_dir() );
        struct dirent *de; UINT *ids = NULL, count = 0, cap = 0;
        if (d) { while ((de = readdir( d ))) {
                UINT id; int i; char sig[4] = { ' ', ' ', ' ', ' ' };
                if (de->d_name[0] == '.') continue;
                if (!strcmp( de->d_name, "data" ) || !strcmp( de->d_name, "dynamic" )) continue;
                for (i = 0; i < 4 && de->d_name[i]; i++) sig[i] = de->d_name[i];
                id = (unsigned char)sig[0] | ((unsigned char)sig[1] << 8) | ((unsigned char)sig[2] << 16) | ((unsigned char)sig[3] << 24);
                if (count == cap) { cap = cap ? cap * 2 : 64; ids = realloc( ids, cap * sizeof(UINT) ); }
                ids[count++] = id; }
            closedir( d ); }
        len = count * sizeof(UINT);
        sfti->TableBufferLength = len;
        *required_len = offsetof( SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer[len] );
        if (available_len < *required_len) { free( ids ); return STATUS_BUFFER_TOO_SMALL; }
        if (ids) memcpy( sfti->TableBuffer, ids, len );
        free( ids );
        return STATUS_SUCCESS;
    }
'''
        t = must_replace(t, enum_anchor, enum_case, "enum RSMB return")
        get_anchor = "        memcpy( sfti->TableBuffer, smbios_data, len );\n        return STATUS_SUCCESS;\n"
        get_case = get_anchor + r'''
    case ACPI:
    {
        char path[320], sig[5] = { 0 }; FILE *f; long fsize; size_t got;
        sig[0] = sfti->TableID & 0xff; sig[1] = (sfti->TableID >> 8) & 0xff;
        sig[2] = (sfti->TableID >> 16) & 0xff; sig[3] = (sfti->TableID >> 24) & 0xff;
        snprintf( path, sizeof(path), "%s/%s", acpi_tables_dir(), sig );
        if (!(f = fopen( path, "rb" ))) { snprintf( path, sizeof(path), "%s/%s1", acpi_tables_dir(), sig ); f = fopen( path, "rb" ); }
        if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
        fseek( f, 0, SEEK_END ); fsize = ftell( f ); fseek( f, 0, SEEK_SET );
        if (fsize <= 0) { fclose( f ); return STATUS_OBJECT_NAME_NOT_FOUND; }
        len = fsize; sfti->TableBufferLength = len;
        *required_len = offsetof( SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer[len] );
        if (available_len < *required_len) { fclose( f ); return STATUS_BUFFER_TOO_SMALL; }
        got = fread( sfti->TableBuffer, 1, len, f ); fclose( f );
        if (got != len) return STATUS_UNSUCCESSFUL;
        return STATUS_SUCCESS;
    }
'''
        t = must_replace(t, get_anchor, get_case, "get RSMB return")
    if "get_smbios_sku" not in t:
        sku_helper = ('static const char *get_smbios_sku( char *str, size_t size )\n{\n'
                      '    unsigned int i, run;\n'
                      '    get_smbios_string( "/sys/class/dmi/id/product_sku", str, size );\n'
                      '    for (i = 0; str[i]; i++) {\n'
                      '        for (run = 1; str[i+run] && str[i+run] == str[i]; run++) {}\n'
                      '        if (run >= 4) { strcpy( str, "1Z4Q7" ); break; }\n'
                      '        for (run = 1; str[i+run] && str[i+run] == (char)(str[i+run-1] + 1); run++) {}\n'
                      '        if (run >= 4) { strcpy( str, "1Z4Q7" ); break; }\n'
                      '    }\n    return str;\n}\n\n'
                      'static struct smbios_prologue *create_smbios_data(void)\n{\n'
                      '    char vendor[128], version[128], date[128], product[128], serial[128];')
        t = must_replace(t,
                         'static struct smbios_prologue *create_smbios_data(void)\n{\n'
                         '    char vendor[128], version[128], date[128], product[128], serial[128];',
                         sku_helper, "create_smbios_data (linux)")
        t = must_replace(t, 'get_smbios_string( "/sys/class/dmi/id/product_sku", S(sku) )',
                         'get_smbios_sku( S(sku) )', "product_sku read")
    open(path, "w").write(t); print("  system.c patched" if t != o else "  system.c unchanged")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wine_root")
    ap.add_argument("--acpi-dir", default="/var/lib/wine-cloak/acpi")
    a = ap.parse_args()
    print(f"[source] patching {a.wine_root} (ACPI cache: {a.acpi_dir})")
    patch_builtin(f"{a.wine_root}/dlls/wbemprox/builtin.c")
    patch_system(f"{a.wine_root}/dlls/ntdll/unix/system.c", a.acpi_dir)
    print("[source] done")

if __name__ == "__main__":
    main()
