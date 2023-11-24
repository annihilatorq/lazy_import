# lazy_import

Lazy Import technique implementation to call any import in the runtime. It will be very useful for calling undocumented functions, as well as for making it difficult for a reverse engineer to analyze your binary file, more specifically - calls to various APIs.
The implementation also includes call caching for speed and optimization purposes.

Currently supports and tested only: MSVC compiler, x64-x86 Debug/Release, `std::c++14 - std::c++23`

### Quick example
```cpp
LI(int, MessageBoxA).call(nullptr, "Hello world.", "Goodbye world...", MB_OK);
```

> [!IMPORTANT]\
> With this call you can call absolutely any export from the DLL module you need, this is useful for conveniently calling undocumented functions.

## Detailed example

```cpp
int main(void)
{
    // We need to load a module that contains MessageBoxA export.
    LoadLibraryA("user32.dll");

    // Creating an instance (not necessarily)
    auto instance = LI(int, MessageBoxA); // or LI_FROM(int, "user32.dll", MessageBoxA);

    // MessageBoxA default call
    int result = instance.call(nullptr, "Hello world.", "Goodbye world...", MB_OK);

    // MessageBoxA cached call
    for (int i = 0; i < 5; ++i)
        result = instance.cached_call(nullptr, "Hello world.", "Goodbye world...", MB_OK);

    // Check for return value
    std::cout << "Last MessageBoxA returned: " << result << '\n';

    return EXIT_SUCCESS;
}
```

## 🚀 Features

- Ability to cache every call.
- Ability to disable exceptions within the code.
- Doesn't leave any strings in executable memory (exclude exceptions).
- Compile-time import name hashing.
- Doesn't leave any imports in the executable.
- Header includes only `<intrin.h>` so that the compilation time is minimized.

## 🛠️ Configuration

| `#define`                                 | EFFECT                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `LAZY_IMPORT_DISABLE_FORCEINLINE`         | disables force inlining                                                                 |
| `LAZY_IMPORT_DISABLE_EXCEPTIONS`          | disables all exceptions and returns 0 if the function fails.                            |
| `LAZY_IMPORT_CASE_INSENSITIVE`            | disables case sensitivity in the hashing algorithm                                      |

## IDA Pro Pseudocode Output
Build configuration: MSVC compiler, Release x64, std::c++23 std::c17, /O2 flag.

`#define LAZY_IMPORT_DISABLE_EXCEPTIONS`
```c
__int64 __fastcall li_call(__int64 a1, __int64 import_hash)
{
  __int64 v2; // r14
  PVOID *v4; // rcx
  PVOID *v5; // r12
  int *v6; // r11
  __int64 v7; // rax
  _DWORD *v8; // rbp
  unsigned int v9; // eax
  __int64 v10; // rsi
  unsigned int *v11; // rdi
  __int64 v12; // r15
  __int64 v13; // r10
  char *v14; // rbx
  int v15; // eax
  char v16; // r9
  char v17; // dl
  int v18; // ecx
  int v19; // eax
  PVOID *v21; // [rsp+30h] [rbp+8h]

  v2 = 0i64;
  v4 = &NtCurrentPeb()->Ldr->Reserved2[1];
  v21 = v4;
  v5 = (PVOID *)*v4;
  if ( *v4 == v4 )
    return 0i64;
  while ( 1 )
  {
    if ( v5[12] )
    {
      v6 = (int *)v5[6];
      if ( v6 )
      {
        v7 = v6[15];
        v8 = (int *)((char *)v6 + *(unsigned int *)((char *)v6 + v7 + 136));
        if ( *(_WORD *)v6 == 23117 && (*(_WORD *)((char *)v6 + v7 + 24) != 523 || *(int *)((char *)v6 + v7 + 140)) )
        {
          v9 = v8[6];
          if ( v9 )
          {
            v10 = 0i64;
            v11 = (unsigned int *)((char *)v6 + (unsigned int)v8[8]);
            v12 = v9;
            do
            {
              LODWORD(v13) = 0;
              v14 = (char *)v6 + *v11;
              v15 = 46051127;
              v16 = *v14;
              if ( *v14 )
              {
                do
                {
                  v17 = v16 + 32;
                  v18 = v13;
                  if ( (unsigned __int8)(v16 - 65) > 0x19u )
                    v17 = v16;
                  v19 = v17 * (v13 + 46051127) + (v17 ^ v15);
                  if ( !(_DWORD)v13 )
                    v18 = 46051127;
                  v13 = (unsigned int)(v13 + 1);
                  v16 = v14[v13];
                  v15 = v17 + (v18 ^ 0x2BEAF37) * v19;
                }
                while ( v16 );
                v6 = (int *)v5[6];
              }
              if ( import_hash == v15 )
                v2 = (__int64)v6
                   + *(unsigned int *)((char *)&v6[*(unsigned __int16 *)((char *)v6 + v10 + (unsigned int)v8[9])]
                                     + (unsigned int)v8[7]);
              ++v11;
              v10 += 2i64;
              --v12;
            }
            while ( v12 );
            v4 = v21;
          }
          if ( v2 )
            break;
        }
      }
    }
    v5 = (PVOID *)*v5;
    if ( v5 == v4 )
      return 0i64;
  }
  return v2;
}
```

> [!NOTE]\
> If you notice any bug or error while using this repository - create an `Issue`, describe your problem in as much detail as possible and I will try to release a fix soon.
