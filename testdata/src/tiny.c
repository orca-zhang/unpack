/* Benign fixture: no system dependencies, file/network access or subprocesses. */
volatile unsigned char fixture_data[65536] = "unpack fixture: reproducible executable sample";
__attribute__((noinline)) int fixture_helper(void) { return fixture_data[0]; }
int entry(void) {
    int result = fixture_helper() == 'u' ? 0 : 1;
#if defined(__linux__) && defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60), "D"(result) : "rcx", "r11", "memory");
    __builtin_unreachable();
#elif defined(__linux__) && defined(__i386__)
    __asm__ volatile("int $0x80" : : "a"(1), "b"(result) : "memory");
    __builtin_unreachable();
#elif defined(__linux__) && defined(__aarch64__)
    register long status __asm__("x0") = result;
    register long syscall_number __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(status), "r"(syscall_number) : "memory");
    __builtin_unreachable();
#else
    return result;
#endif
}
