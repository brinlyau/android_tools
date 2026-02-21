Just a few Android internals related tools that I wanted to open source because I keep writing the same thing at every job I ever had.

# android_tools

A collection of standalone tools for Android kernel and firmware analysis.


## Tools and scripts

### extract-kallsyms

Extracts the kernel symbol table (`kallsyms`) from a `boot.img` or raw kernel image. Handles boot image header versions 0-4, LZ4 and gzip compressed kernels, and both pre-6.4 and 6.4+ kallsyms layouts (relative and absolute addresses). Self-contained with no external dependencies beyond libc.

```
gcc -O2 -Wall -o extract-kallsyms extract-kallsyms.c
./extract-kallsyms -i boot.img -o symbols.txt
./extract-kallsyms -k kernel_image -o symbols.txt
```

### extract_kernel

Extracts the raw kernel binary from Android boot images (`boot.img`, `vendor_kernel_boot.img`). Supports standard boot images, GKI vendor kernel boot images, and ARM64 kernel carving. Includes built-in LZ4 legacy decompression.

```
gcc -O2 -Wall -o extract_kernel extract_kernel.c
./extract_kernel -i vendor_kernel_boot.img -o kernel.raw
```

### Android ;; android_mitigations_chk

Tests the availability of common kernel exploit primitives, kernel features, build prop settings and debugging interfaces on an Android device. Checks heap spray syscalls (add_key, msgsnd, pipe, sockets, xattr, SCM_RIGHTS), race/timing primitives (userfaultfd, epoll, timerfd, signalfd, user namespaces), privilege escalation helpers (bpf), info leak sources (/proc/kallsyms, /proc/iomem, slabinfo), and relevant kernel command line parameters.

```
# Cross-compile for Android
aarch64-linux-android-clang -o android_mitigations_chk android_kernel_mitigations_check.c
adb push android_mitigations_chk /data/local/tmp/
adb shell /data/local/tmp/android_mitigations_chk
```


## See also

- [AfucBinja](https://github.com/brinlyau/AfucBinja/) - Binary Ninja plugin for Adreno GPU microcontroller firmware
