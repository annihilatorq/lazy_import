#ifndef LAZY_IMPORT_HPP
#define LAZY_IMPORT_HPP

#include <intrin.h>

#define LI(type, name) ::lazy_import::internals::lazy_import_internals<type>(LAZY_IMPORT_COMPILETIME_HASH(#name))
#define LI_FROM(type, module_name, import_name) ::lazy_import::internals::lazy_import_internals<type, LAZY_IMPORT_COMPILETIME_HASH(module_name)>(LAZY_IMPORT_COMPILETIME_HASH(#import_name))

#ifndef LAZY_IMPORT_DISABLE_EXCEPTIONS
#define LAZY_IMPORT_EXCEPTION_HANDLING false
#else
#define LAZY_IMPORT_EXCEPTION_HANDLING true
#endif

#ifndef LAZY_IMPORT_DISABLE_FORCEINLINE
#if defined(_MSC_VER)
#define LAZY_IMPORT_FORCEINLINE __forceinline
#endif
#else
#define LAZY_IMPORT_FORCEINLINE inline
#endif

#if _HAS_CXX20
#define LAZY_IMPORT_CONSTEVAL consteval
#else
#define LAZY_IMPORT_CONSTEVAL constexpr
#endif

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (unsigned long long)(&((type *)0)->field)))
#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
#if defined(_M_X64)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x20b
#elif defined(_M_IX86)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#endif

#ifndef LAZY_IMPORT_CASE_INSENSITIVE
#define LAZY_IMPORT_CASE_SENSITIVITY true
#else
#define LAZY_IMPORT_CASE_SENSITIVITY false
#endif

#define LAZY_IMPORT_TOLOWER(c) ((c >= 'A' && c <= 'Z') ? (c + 32) : c)

#define LAZY_IMPORT_COMPILETIME_HASH(x) []() { constexpr unsigned int hash = ::lazy_import::hash::chash(x); return hash; }()
#define LAZY_IMPORT_RUNTIME_HASH(x) ::lazy_import::hash::hash(x)

namespace lazy_import {
	namespace PE
	{
		struct UNICODE_STRING {
			unsigned short  Length;
			unsigned short  MaximumLength;
			wchar_t* Buffer;
		};

		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* Flink;
			struct _LIST_ENTRY* Blink;
		} LIST_ENTRY, * PLIST_ENTRY, * PRLIST_ENTRY;

		typedef struct _LDR_DATA_TABLE_ENTRY {
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			void* Reserved2[2];
			void* DllBase;
			void* EntryPoint;
			void* Reserved3;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
			void* Reserved5[3];
			union {
				unsigned long CheckSum;
				void* Reserved6;
			};
			unsigned long          TimeDateStamp;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _PEB_LDR_DATA {
			unsigned long Length;
			unsigned char Initialized;
			void* SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		struct PEB {
			unsigned char   Reserved1[2];
			unsigned char   BeingDebugged;
			unsigned char   Reserved2[1];
			const char*		Reserved3[2];
			PEB_LDR_DATA*	LoaderData;
		};

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			unsigned long  Characteristics;
			unsigned long  TimeDateStamp;
			unsigned short MajorVersion;
			unsigned short MinorVersion;
			unsigned long  Name;
			unsigned long  Base;
			unsigned long  NumberOfFunctions;
			unsigned long  NumberOfNames;
			unsigned long  AddressOfFunctions; // RVA from base of image
			unsigned long  AddressOfNames; // RVA from base of image
			unsigned long  AddressOfNameOrdinals; // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

		struct IMAGE_DOS_HEADER { // DOS .EXE header
			unsigned short e_magic; // Magic number
			unsigned short e_cblp; // Bytes on last page of file
			unsigned short e_cp; // Pages in file
			unsigned short e_crlc; // Relocations
			unsigned short e_cparhdr; // Size of header in paragraphs
			unsigned short e_minalloc; // Minimum extra paragraphs needed
			unsigned short e_maxalloc; // Maximum extra paragraphs needed
			unsigned short e_ss; // Initial (relative) SS value
			unsigned short e_sp; // Initial SP value
			unsigned short e_csum; // Checksum
			unsigned short e_ip; // Initial IP value
			unsigned short e_cs; // Initial (relative) CS value
			unsigned short e_lfarlc; // File address of relocation table
			unsigned short e_ovno; // Overlay number
			unsigned short e_res[4]; // Reserved words
			unsigned short e_oemid; // OEM identifier (for e_oeminfo)
			unsigned short e_oeminfo; // OEM information; e_oemid specific
			unsigned short e_res2[10]; // Reserved words
			long           e_lfanew; // File address of new exe header
		};

		struct IMAGE_FILE_HEADER {
			unsigned short Machine;
			unsigned short NumberOfSections;
			unsigned long  TimeDateStamp;
			unsigned long  PointerToSymbolTable;
			unsigned long  NumberOfSymbols;
			unsigned short SizeOfOptionalHeader;
			unsigned short Characteristics;
		};

		struct IMAGE_DATA_DIRECTORY {
			unsigned long VirtualAddress;
			unsigned long Size;
		};

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			unsigned short Magic;
			unsigned char MajorLinkerVersion;
			unsigned char MinorLinkerVersion;
			unsigned long SizeOfCode;
			unsigned long SizeOfInitializedData;
			unsigned long SizeOfUninitializedData;
			unsigned long AddressOfEntryPoint;
			unsigned long BaseOfCode;
			unsigned long long ImageBase;
			unsigned long SectionAlignment;
			unsigned long FileAlignment;
			unsigned short MajorOperatingSystemVersion;
			unsigned short MinorOperatingSystemVersion;
			unsigned short MajorImageVersion;
			unsigned short MinorImageVersion;
			unsigned short MajorSubsystemVersion;
			unsigned short MinorSubsystemVersion;
			unsigned long Win32VersionValue;
			unsigned long SizeOfImage;
			unsigned long SizeOfHeaders;
			unsigned long CheckSum;
			unsigned short Subsystem;
			unsigned short DllCharacteristics;
			unsigned long long SizeOfStackReserve;
			unsigned long long SizeOfStackCommit;
			unsigned long long SizeOfHeapReserve;
			unsigned long long SizeOfHeapCommit;
			unsigned long LoaderFlags;
			unsigned long NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_OPTIONAL_HEADER32 {
			unsigned short       Magic;
			unsigned char        MajorLinkerVersion;
			unsigned char        MinorLinkerVersion;
			unsigned long        SizeOfCode;
			unsigned long        SizeOfInitializedData;
			unsigned long        SizeOfUninitializedData;
			unsigned long        AddressOfEntryPoint;
			unsigned long        BaseOfCode;
			unsigned long        BaseOfData;
			unsigned long        ImageBase;
			unsigned long        SectionAlignment;
			unsigned long        FileAlignment;
			unsigned short       MajorOperatingSystemVersion;
			unsigned short       MinorOperatingSystemVersion;
			unsigned short       MajorImageVersion;
			unsigned short       MinorImageVersion;
			unsigned short       MajorSubsystemVersion;
			unsigned short       MinorSubsystemVersion;
			unsigned long        Win32VersionValue;
			unsigned long        SizeOfImage;
			unsigned long        SizeOfHeaders;
			unsigned long        CheckSum;
			unsigned short       Subsystem;
			unsigned short       DllCharacteristics;
			unsigned long        SizeOfStackReserve;
			unsigned long        SizeOfStackCommit;
			unsigned long        SizeOfHeapReserve;
			unsigned long        SizeOfHeapCommit;
			unsigned long        LoaderFlags;
			unsigned long        NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

		typedef struct _IMAGE_NT_HEADERS {
#if defined(_M_X64)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER64;
#elif defined(_M_IX86)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER32;
#endif
			unsigned long Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPT_HEADER_ARCH OptionalHeader;
		} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;
	}

	using pointer_t = unsigned long long;

#ifndef LAZY_IMPORT_DISABLE_EXCEPTIONS
	namespace exception
	{
		class simplest_exception
		{
		public:
			simplest_exception(const char* message) : m_message(message) {}

			const char* what() const noexcept 
			{
				return m_message;
			}

		private:
			const char* m_message;
		};
	}
#endif

	namespace hash
	{
		constexpr unsigned int magic_value = (__TIME__[1] + __TIME__[4] + __TIME__[6] + __TIME__[7]) * 0x3129392013;

		template<class CharT = char>
		LAZY_IMPORT_FORCEINLINE constexpr unsigned int hash_single_char(unsigned int offset, unsigned int index, CharT c)
		{
			return static_cast<unsigned int>(c + ((offset ^ c) + (magic_value + index) * c) *
				(magic_value ^ (index == 0 ? magic_value : index)));
		}

		template<bool CaseSensitive = LAZY_IMPORT_CASE_SENSITIVITY>
		LAZY_IMPORT_FORCEINLINE LAZY_IMPORT_CONSTEVAL unsigned int chash(const char* str) noexcept
		{
			unsigned int result = magic_value;

			for (unsigned int i = 0; ; i++)
			{
				char c = str[i];
				if (c == '\0') break;
				result = hash_single_char(result, i, CaseSensitive ? LAZY_IMPORT_TOLOWER(c) : c);
			}

			return result;
		}

		template<class CharT = char, bool CaseSensitive = LAZY_IMPORT_CASE_SENSITIVITY>
		LAZY_IMPORT_FORCEINLINE const unsigned int hash(const CharT* str) noexcept
		{
			unsigned int result = magic_value;

			for (unsigned int i = 0; ; i++)
			{
				CharT c = str[i];
				if (c == '\0') break;
				result = hash_single_char<CharT>(result, i, static_cast<CharT>(CaseSensitive ? LAZY_IMPORT_TOLOWER(c) : c));
			}

			return result;
		}
	}

	namespace utils
	{
		LAZY_IMPORT_FORCEINLINE const ::lazy_import::PE::PEB* get_ppeb() noexcept
		{
#if defined(_M_X64)
			return reinterpret_cast<const ::lazy_import::PE::PEB*>(__readgsqword(0x60));
#elif defined(_M_IX86)
			return reinterpret_cast<const ::lazy_import::PE::PEB*>(__readfsdword(0x30));
#endif
		}

		LAZY_IMPORT_FORCEINLINE const ::lazy_import::PE::PIMAGE_NT_HEADERS nt_header(
			pointer_t module_base) noexcept
		{
			return reinterpret_cast<::lazy_import::PE::PIMAGE_NT_HEADERS>(module_base + reinterpret_cast<const ::lazy_import::PE::IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
		}

		LAZY_IMPORT_FORCEINLINE const ::lazy_import::PE::IMAGE_DOS_HEADER* dos_header(
			pointer_t module_base) noexcept
		{
			return reinterpret_cast<::lazy_import::PE::IMAGE_DOS_HEADER*>(module_base);
		}

		LAZY_IMPORT_FORCEINLINE const ::lazy_import::PE::IMAGE_NT_HEADERS::IMAGE_OPT_HEADER_ARCH* optional_header(
			pointer_t module_base) noexcept
		{
			return &nt_header(module_base)->OptionalHeader;
		}

		LAZY_IMPORT_FORCEINLINE const pointer_t dll_base(
			::lazy_import::PE::_LDR_DATA_TABLE_ENTRY* table_entry) noexcept
		{
			return reinterpret_cast<pointer_t>(table_entry->DllBase);
		}

		LAZY_IMPORT_FORCEINLINE ::lazy_import::PE::PEB_LDR_DATA* loader_data() noexcept
		{
			return reinterpret_cast<::lazy_import::PE::PEB_LDR_DATA*>(get_ppeb()->LoaderData);
		}
	}

	namespace detail
	{
		class module_export_info {
		public:
			using const_pointer_t = const pointer_t;

			LAZY_IMPORT_FORCEINLINE module_export_info(
				const_pointer_t base) noexcept : m_base(base)
			{
				const auto export_dir_data = ::lazy_import::utils::nt_header(base)->OptionalHeader.DataDirectory[0];
				m_export_dir = reinterpret_cast<const ::lazy_import::PE::PIMAGE_EXPORT_DIRECTORY>(base + export_dir_data.VirtualAddress);
			}

			LAZY_IMPORT_FORCEINLINE unsigned long size() const noexcept 
			{ 
				return m_export_dir->NumberOfNames;
			}

			LAZY_IMPORT_FORCEINLINE const char* const name(
				unsigned int iterator) const noexcept
			{
				return reinterpret_cast<const char*>(m_base + reinterpret_cast<const unsigned long*>(m_base + m_export_dir->AddressOfNames)[iterator]);
			}

			LAZY_IMPORT_FORCEINLINE const_pointer_t address(
				unsigned int iterator) const noexcept
			{
				const auto rva_table = reinterpret_cast<unsigned long*>(m_base + m_export_dir->AddressOfFunctions);
				const auto ord_table = reinterpret_cast<unsigned short*>(m_base + m_export_dir->AddressOfNameOrdinals);
				return m_base + rva_table[ord_table[iterator]];
			}

			LAZY_IMPORT_FORCEINLINE bool module_integrity_checks() noexcept(LAZY_IMPORT_EXCEPTION_HANDLING)
			{
				if (::lazy_import::utils::dos_header(m_base)->e_magic != IMAGE_DOS_SIGNATURE)
				{
#ifndef LAZY_IMPORT_DISABLE_EXCEPTIONS
					throw ::lazy_import::exception::simplest_exception("DOS header e_magic mismatch");
#else
					return false;
#endif
				}

				if (::lazy_import::utils::nt_header(m_base)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
					::lazy_import::utils::optional_header(m_base)->DataDirectory[0].Size <= 0ul)
				{
					return false;
				}

				return true;
			}

		private:
			const_pointer_t m_base;
			const ::lazy_import::PE::IMAGE_EXPORT_DIRECTORY* m_export_dir;
		};

		template<unsigned int ModuleHash = 0>
		class import_enumerator
		{
		public:
			using const_pointer_t = const pointer_t;

			LAZY_IMPORT_FORCEINLINE const_pointer_t find_import(
				const_pointer_t import_hash) noexcept(LAZY_IMPORT_EXCEPTION_HANDLING)
			{
				auto entry = &::lazy_import::utils::loader_data()->InLoadOrderModuleList;
				pointer_t import_address = 0;

				for (auto i = entry->Flink; i != entry; i = i->Flink)
				{
					auto module_data = CONTAINING_RECORD(i, ::lazy_import::PE::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					if (module_data->BaseDllName.Buffer == nullptr)
						continue;

					pointer_t module_base = ModuleHash != 0 ? find_target_module(module_data) : ::lazy_import::utils::dll_base(module_data);

					if (module_base == 0)
						continue;

					module_export_info exp(module_base);

					if (!exp.module_integrity_checks())
						continue;

					for (unsigned int i = 0; i < exp.size(); ++i) {
						if (import_hash == LAZY_IMPORT_RUNTIME_HASH(exp.name(i))) {
							import_address = static_cast<const_pointer_t>(exp.address(i));
						}
					}

					if (import_address == 0) {
						continue;
					}

					return import_address;
				}

#ifndef LAZY_IMPORT_DISABLE_EXCEPTIONS
				// Make sure that import name is right and module is loaded.
				throw ::lazy_import::exception::simplest_exception("Cannot find desired import.");
#endif

				return 0;
			}

		private:
			LAZY_IMPORT_FORCEINLINE const_pointer_t find_target_module(
				::lazy_import::PE::LDR_DATA_TABLE_ENTRY* module_data) noexcept
			{
				if (ModuleHash == ::lazy_import::hash::hash<wchar_t>(module_data->BaseDllName.Buffer))
					return ::lazy_import::utils::dll_base(module_data);

				return 0;
			}
		};
	}

	namespace internals
	{
		template <class ReturnType, unsigned int ModuleHash = 0>
		class lazy_import_internals
		{
		public:
			LAZY_IMPORT_FORCEINLINE lazy_import_internals(unsigned int import_hash) noexcept : m_import_hash(import_hash) {}

			template<class... Args>
			LAZY_IMPORT_FORCEINLINE ReturnType call(Args... args) noexcept
			{
				detail::import_enumerator<ModuleHash> e;
				pointer_t import_address = e.find_import(m_import_hash);
				return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(import_address)(args...);
			}

			template<class... Args>
			LAZY_IMPORT_FORCEINLINE ReturnType cached_call(Args... args) noexcept
			{
				pointer_t& cache_addr = cached_address();
				if (cache_addr == 0) {
					detail::import_enumerator<ModuleHash> e;
					cache_addr = e.find_import(m_import_hash);
				}

				return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(cache_addr)(args...);
			}

		private:
			unsigned int m_import_hash = 0;

			template<class T = pointer_t>
			LAZY_IMPORT_FORCEINLINE static T& cached_address() noexcept
			{
				static T cached_val = 0;
				return cached_val;
			}
		};
	}
}

#endif // LAZY_IMPORT_HPP
