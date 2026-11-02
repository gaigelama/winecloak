/* winecheck.c — probe the common "am I running under Wine?" signals.
 * Returns non-zero if any signal fires. Build with mingw-w64 (32 and 64 bit). */
#include <windows.h>
#include <stdio.h>

int main(void) {
    int detected = 0;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    const char *exp[] = { "wine_get_version", "wine_get_build_id", "wine_get_host_version" };
    for (int i = 0; i < 3; i++) {
        FARPROC p = GetProcAddress(nt, exp[i]);
        printf("  ntdll!%-22s = %-18p %s\n", exp[i], (void*)p,
               p ? "<-- WINE DETECTED" : "(not found)");
        if (p) detected = 1;
    }

    HKEY k;
    LONG r = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Wine", 0, KEY_READ, &k);
    printf("  HKCU\\Software\\Wine            = %s\n",
           r == ERROR_SUCCESS ? "PRESENT          <-- WINE TELL" : "absent");
    if (r == ERROR_SUCCESS) { RegCloseKey(k); detected = 1; }

    DWORD a = GetFileAttributesA("C:\\windows\\system32\\winemenubuilder.exe");
    printf("  C:\\..\\winemenubuilder.exe     = %s\n",
           a != INVALID_FILE_ATTRIBUTES ? "PRESENT          <-- WINE TELL" : "absent");
    if (a != INVALID_FILE_ATTRIBUTES) detected = 1;

    char buf[8]; DWORD n = GetEnvironmentVariableA("WINEPREFIX", buf, sizeof buf);
    printf("  env WINEPREFIX                = %s\n",
           n ? "SET              <-- WINE TELL" : "unset");
    if (n) detected = 1;

    printf("\n  VERDICT: %s\n", detected ? "WINE DETECTABLE" : "clean on these checks");
    return detected;
}
