#ifndef LAZY_IMPORT_HPP
#define LAZY_IMPORT_HPP

#include <intrin.h>

#define LI(type, name) ::lazy_import::internals::lazy_import_internals<type>(LAZY_IMPORT_COMPILETIME_HASH(#name))
#define LI_FROM(type, module_name, import_name) ::lazy_import::internals::lazy_import_internals<type, LAZY_IMPORT_COMPILETIME_HASH(module_name)>(LAZY_IMPORT_COMPILETIME_HASH(#import_name))

#ifndef LAZY_IMPORT_DISABLE_CACHING
#include <unordered_map>
#endif

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
			unsigned short length;
			unsigned short maximum_length;
			wchar_t* buffer;
		};

		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* flink;
			struct _LIST_ENTRY* blink;
		} LIST_ENTRY, * PLIST_ENTRY, * PRLIST_ENTRY;

		typedef struct _LDR_DATA_TABLE_ENTRY {
			LIST_ENTRY in_load_order_links;
			LIST_ENTRY in_memory_order_links;
			void* reserved2[2];
			void* dll_base;
			void* entry_point;
			void* reserved3;
			UNICODE_STRING full_dll_name;
			UNICODE_STRING base_dll_name;
			void* reserved5[3];
			union {
				unsigned long check_sum;
				void* reserved6;
			};
			unsigned long time_date_stamp;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _PEB_LDR_DATA {
			unsigned long length;
			unsigned char initialized;
			void* ss_handle;
			LIST_ENTRY in_load_order_module_list;
			LIST_ENTRY in_memory_order_module_list;
			LIST_ENTRY in_initialization_order_module_list;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		struct PEB {
			unsigned char   reserved1[2];
			unsigned char   being_debugged;
			unsigned char   reserved2[1];
			const char*		reserved3[2];
			PEB_LDR_DATA*	loader_data;
		};

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			unsigned long  characteristics;
			unsigned long  time_date_stamp;
			unsigned short major_version;
			unsigned short minor_version;
			unsigned long  name;
			unsigned long  base;
			unsigned long  number_of_functions;
			unsigned long  number_of_names;
			unsigned long  address_of_functions; // RVA from base of image
			unsigned long  address_of_names; // RVA from base of image
			unsigned long  address_of_name_ordinals; // RVA from base of image
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
			unsigned short machine;
			unsigned short number_of_sections;
			unsigned long  time_date_stamp;
			unsigned long  pointer_to_symbol_table;
			unsigned long  number_of_symbols;
			unsigned short size_of_optional_header;
			unsigned short characteristics;
		};

		struct IMAGE_DATA_DIRECTORY {
			unsigned long virtual_address;
			unsigned long size;
		};

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			unsigned short magic;
			unsigned char major_linker_version;
			unsigned char minor_linker_version;
			unsigned long size_of_code;
			unsigned long size_of_initialized_data;
			unsigned long size_of_uninitialized_data;
			unsigned long address_of_entry_point;
			unsigned long base_of_code;
			unsigned long long image_base;
			unsigned long section_alignment;
			unsigned long file_alignment;
			unsigned short major_operating_system_version;
			unsigned short minor_operation_system_version;
			unsigned short major_image_version;
			unsigned short minor_image_version;
			unsigned short major_subsystem_version;
			unsigned short minor_subsystem_version;
			unsigned long win32_version_value;
			unsigned long size_of_image;
			unsigned long size_of_headers;
			unsigned long check_sum;
			unsigned short subsystem;
			unsigned short dll_characteristics;
			unsigned long long size_of_stack_reserve;
			unsigned long long size_of_stack_commit;
			unsigned long long size_of_heap_reserve;
			unsigned long long size_of_heap_commit;
			unsigned long loader_flags;
			unsigned long number_of_rva_and_sizes;
			IMAGE_DATA_DIRECTORY data_directory[16];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_OPTIONAL_HEADER32 {
			unsigned short       magic;
			unsigned char        major_linker_version;
			unsigned char        minor_linker_version;
			unsigned long        size_of_code;
			unsigned long        size_of_initialized_data;
			unsigned long        size_of_uninitialized_data;
			unsigned long        address_of_entry_point;
			unsigned long        base_of_code;
			unsigned long        base_of_data;
			unsigned long        image_base;
			unsigned long        section_alignment;
			unsigned long        file_alignment;
			unsigned short       major_operating_system_version;
			unsigned short       minor_operation_system_version;
			unsigned short       major_image_version;
			unsigned short       minor_image_version;
			unsigned short       major_subsystem_version;
			unsigned short       minor_subsystem_version;
			unsigned long        win32_version_value;
			unsigned long        size_of_image;
			unsigned long        size_of_headers;
			unsigned long        check_sum;
			unsigned short       subsystem;
			unsigned short       dll_characteristics;
			unsigned long        size_of_stack_reserve;
			unsigned long        size_of_stack_commit;
			unsigned long        size_of_heap_reserve;
			unsigned long        size_of_heap_commit;
			unsigned long        loader_flags;
			unsigned long        number_of_rva_and_sizes;
			IMAGE_DATA_DIRECTORY data_directory[16];
		} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

		typedef struct _IMAGE_NT_HEADERS {
#if defined(_M_X64)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER64;
#elif defined(_M_IX86)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER32;
#endif
			unsigned long signature;
			IMAGE_FILE_HEADER file_header;
			IMAGE_OPT_HEADER_ARCH optional_header;
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
		namespace string
		{
			LAZY_IMPORT_FORCEINLINE const char* strtrim(
				const char* str, char delimiter)
			{
				const char* result = str;
				while (*str != '\0') {
					if (*str == delimiter) {
						result = str + 1;
					}
					str++;
				}
				return result;
			}
		}

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
			return &nt_header(module_base)->optional_header;
		}

		LAZY_IMPORT_FORCEINLINE const pointer_t dll_base(
			::lazy_import::PE::_LDR_DATA_TABLE_ENTRY* table_entry) noexcept
		{
			return reinterpret_cast<pointer_t>(table_entry->dll_base);
		}

		LAZY_IMPORT_FORCEINLINE ::lazy_import::PE::PEB_LDR_DATA* loader_data() noexcept
		{
			return reinterpret_cast<::lazy_import::PE::PEB_LDR_DATA*>(get_ppeb()->loader_data);
		}

#ifndef LAZY_IMPORT_DISABLE_CACHING
		template <class _Type1, class _Type2 = _Type1>
		LAZY_IMPORT_FORCEINLINE const bool value_stored_in_map(
			std::unordered_map<_Type1, _Type2> _map, _Type1 _key) noexcept
		{
			return (_map.find(_key) != _map.end());
		}
#endif
	}

	namespace detail
	{
		class module_export_info {
		public:
			using const_pointer_t = const pointer_t;

			LAZY_IMPORT_FORCEINLINE module_export_info(
				const_pointer_t base) noexcept : m_base(base)
			{
				const auto export_dir_data = ::lazy_import::utils::nt_header(base)->optional_header.data_directory[0];
				m_export_dir = reinterpret_cast<const ::lazy_import::PE::PIMAGE_EXPORT_DIRECTORY>(base + export_dir_data.virtual_address);
			}

			LAZY_IMPORT_FORCEINLINE unsigned long size() const noexcept 
			{ 
				return m_export_dir->number_of_names;
			}

			LAZY_IMPORT_FORCEINLINE const char* const name(
				unsigned int iterator) const noexcept
			{
				return reinterpret_cast<const char*>(m_base + reinterpret_cast<const unsigned long*>(m_base + m_export_dir->address_of_names)[iterator]);
			}

			LAZY_IMPORT_FORCEINLINE const_pointer_t address(
				unsigned int iterator) const noexcept
			{
				const auto rva_table = reinterpret_cast<unsigned long*>(m_base + m_export_dir->address_of_functions);
				const auto ord_table = reinterpret_cast<unsigned short*>(m_base + m_export_dir->address_of_name_ordinals);
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

				if (::lazy_import::utils::nt_header(m_base)->optional_header.magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
					::lazy_import::utils::optional_header(m_base)->data_directory[0].size <= 0ul)
				{
					return false;
				}

				return true;
			}

			LAZY_IMPORT_FORCEINLINE bool is_forwarded_export(const_pointer_t ptr) noexcept
			{
				::lazy_import::PE::IMAGE_DATA_DIRECTORY export_dir = 
					::lazy_import::utils::optional_header(m_base)->data_directory[0];

				const_pointer_t export_table_start = m_base + export_dir.virtual_address;
				const_pointer_t export_table_end = export_table_start + export_dir.size;

				return (ptr >= export_table_start) && (ptr < export_table_end);
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
				auto entry = &::lazy_import::utils::loader_data()->in_load_order_module_list;
				bool forward_check = false;
				pointer_t import_address = 0;

				for (auto i = entry->flink; i != entry; i = i->flink)
				{
					auto module_data = CONTAINING_RECORD(i, ::lazy_import::PE::LDR_DATA_TABLE_ENTRY, in_load_order_links);

					if (module_data->base_dll_name.buffer == nullptr)
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

							// HeapAlloc, HeapReAlloc, HeapFree, etc.
							if (exp.is_forwarded_export(import_address)) {
								auto str = reinterpret_cast<const char*>(import_address);
								auto substr = ::lazy_import::utils::string::strtrim(str, '.');

								return find_import(LAZY_IMPORT_RUNTIME_HASH(substr));
							}

							break;
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
				if (ModuleHash == ::lazy_import::hash::hash<wchar_t>(module_data->base_dll_name.buffer))
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
				pointer_t import_address = 0;
#ifndef LAZY_IMPORT_DISABLE_CACHING
				if (::lazy_import::utils::value_stored_in_map(m_ptr_map, m_import_hash)) {
					import_address = m_ptr_map.at(m_import_hash);
				}
				else
				{
					detail::import_enumerator<ModuleHash> e;
					import_address = e.find_import(m_import_hash);
					m_ptr_map.insert(std::make_pair(m_import_hash, import_address));
				}
#else
				detail::import_enumerator<ModuleHash> e;
				import_address = e.find_import(m_import_hash);
#endif

				return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(import_address)(args...);
			}

		private:
			unsigned int m_import_hash = 0;
#ifndef LAZY_IMPORT_DISABLE_CACHING
			static inline std::unordered_map<unsigned int, pointer_t> m_ptr_map;
#endif
		};
	}
}

#endif // LAZY_IMPORT_HPP
