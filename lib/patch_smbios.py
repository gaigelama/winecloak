#!/usr/bin/env python3
r"""Add per-prefix SMBIOS overrides to wine (dlls/ntdll/unix/system.c), so each prefix
can present a unique machine UUID + serials (defeats cross-container machine-ID tracking).

Wine reads overrides from  $WINEPREFIX/.wine-cloak-smbios  (key=value lines):
    machineid=<32 hex>        -> system/product UUID (else host /var/lib/dbus/machine-id)
    system_serial=<str>       -> Win32_ComputerSystemProduct IdentifyingNumber / BIOS serial
    board_serial=<str>        -> baseboard serial
    chassis_serial=<str>      -> chassis serial
Absent file or key => original host behavior.

Usage: patch_smbios.py <wine-src-root>
"""
import sys

HELPER = r'''
/* --- wine-cloak: per-prefix SMBIOS overrides (unique machine id per container) --- */
extern const char *config_dir;
static int wine_cloak_read_override( const char *key, char *out, size_t len )
{
    char path[4096], line[512];
    FILE *f;
    size_t kl = strlen( key );
    int ret = 0;
    if (!config_dir || !len) return 0;
    snprintf( path, sizeof(path), "%s/.wine-cloak-smbios", config_dir );
    if (!(f = fopen( path, "r" ))) return 0;
    while (fgets( line, sizeof(line), f ))
    {
        if (!strncmp( line, key, kl ) && line[kl] == '=' )
        {
            char *v = line + kl + 1;
            v[strcspn( v, "\r\n" )] = 0;
            { size_t n = strlen( v ); if (n >= len) n = len - 1; memcpy( out, v, n ); out[n] = 0; }
            ret = (int)strlen( v );
            break;
        }
    }
    fclose( f );
    return ret;
}

static GUID *get_system_uuid( GUID *uuid )'''

def main():
    p = f"{sys.argv[1]}/dlls/ntdll/unix/system.c"
    t = open(p).read(); o = t
    if "wine_cloak_read_override" in t:
        print("  smbios override already present"); return

    # 1) insert helper immediately before get_system_uuid's definition
    t = t.replace("static GUID *get_system_uuid( GUID *uuid )", HELPER, 1)

    # 2) UUID: source the 32-hex machine id from the per-prefix override when present
    old_open = ('    int fd;\n\n'
                '    memset( uuid, 0xff, sizeof(*uuid) );\n'
                '    if ((fd = open( "/var/lib/dbus/machine-id", O_RDONLY )) != -1)\n'
                '    {\n'
                '        unsigned char buf[32], *p = buf;\n'
                '        if (read( fd, buf, sizeof(buf) ) == sizeof(buf))\n'
                '        {')
    new_open = ('    int fd;\n'
                '    char ov[64];\n'
                '    unsigned char buf[32], *p = buf;\n'
                '    int have = 0;\n\n'
                '    memset( uuid, 0xff, sizeof(*uuid) );\n'
                '    if (wine_cloak_read_override( "machineid", ov, sizeof(ov) ) >= 32)\n'
                '    {\n'
                '        memcpy( buf, ov, 32 );\n'
                '        have = 1;\n'
                '    }\n'
                '    else if ((fd = open( "/var/lib/dbus/machine-id", O_RDONLY )) != -1)\n'
                '    {\n'
                '        if (read( fd, buf, sizeof(buf) ) == sizeof(buf)) have = 1;\n'
                '        close( fd );\n'
                '        fd = -1;\n'
                '    }\n'
                '    if (have)\n'
                '    {\n'
                '        {')
    assert old_open in t, "get_system_uuid open-block anchor not found"
    t = t.replace(old_open, new_open, 1)
    # close the extra brace we opened, and drop the now-duplicate close(fd) path
    old_close = ('            uuid->Data4[7] = hex[p[30]] << 4 | hex[p[31]];\n'
                 '        }\n'
                 '        close( fd );\n'
                 '    }\n'
                 '    return uuid;\n'
                 '}')
    new_close = ('            uuid->Data4[7] = hex[p[30]] << 4 | hex[p[31]];\n'
                 '        }\n'
                 '    }\n'
                 '    return uuid;\n'
                 '}')
    assert old_close in t, "get_system_uuid close anchor not found"
    t = t.replace(old_close, new_close, 1)

    # 3) serials: check the per-prefix override first
    for fn, key in (('get_system_serial', 'system_serial'),
                    ('get_board_serial', 'board_serial'),
                    ('get_chassis_serial', 'chassis_serial')):
        # inject right after the function's opening brace line
        anchor = f'static const char *{fn}( char *str, size_t size'
        idx = t.find(anchor)
        if idx < 0:
            print(f"  (skip {fn}: not found)"); continue
        brace = t.find('{', idx)
        inject = (f'{{\n    if (wine_cloak_read_override( "{key}", str, size ) > 0) return str;\n')
        t = t[:brace] + inject + t[brace+1:]

    if t != o:
        open(p, "w").write(t); print("  system.c: per-prefix SMBIOS overrides added")

if __name__ == "__main__":
    main()
