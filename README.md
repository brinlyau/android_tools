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


## See also

- [AfucBinja](https://github.com/brinlyau/AfucBinja/) - Binary Ninja plugin for Adreno GPU microcontroller firmware
