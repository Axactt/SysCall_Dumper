#include<iostream>
#include<windows.h>
#include"ReNtdll.h" //!Header indlude from x64dbg project, defines lots of undocumented structures


extern "C" //! extern "C" namespace to prvent name-mangling

{

	void asmSysCaller();

}




//!Usinf custom getModuleHandle function using LDR_DATA_TABLE_ENTRY
//! Using getTEB/getPEB from gs-register_base to get TIB and PEB for LDR_DATA_TABLE_ENTRY structure

// Read Peb and module base internally without using windows api.

//! Read the value of TIB or _TEB Linear address from FS/GS segment base offset
//! The TIB of the current thread can be accessed as an offset of segment register FS (x86) or GS (x64).

TEB* getTIBFileLess()
{
	//! _WIN64 is defined on every platform/CPU architecture where sizeof(void*) >= 8
#ifdef _WIN64 //? this macro needs only one undrscore
	TEB* teb = (TEB*) __readgsqword( 0x30 );//?always put double underscore before internall structure command
	//xreturn (void*) __readgsqword( 0x30 ); 
#else 
	TEB* teb = (TEB*) __readfsdword( 0x18 );
	//xreturn (void*) __readfsdword( 0x18 );
#endif
	return teb;
}

//! Read the value of _PEB  Linear address from FS/GS segment base offset
//! The PEB of the current thread can be accessed as an offset of segment register FS (x86) or GS (x64).

PEB* getPEBFileLess()
{
	//! _WIN64 is defined on every platform/CPU architecture where sizeof(void*) >= 8
#ifdef _WIN64 //? this macro needs only one undrscore

	PEB* peb = (PEB*) __readgsqword( 0x60 ); //?always put double underscore before internall structure command
#else 
	PEB* peb = (PEB*) __readfsdword( 0x30 );
#endif
	return peb;
}

//!Once we have got the PEB we can access the PEB_LDR_DATA linked list
//! LDR_DATA_ENTRY LIST_ENTRY a stable structure which list various loaded modules properties
//! WINTERNL.H presents a modified LDR_DATA_TABLE_ENTRY that has just the InMemoryOrderLinks, DllBase, FullDllName, CheckSum and TimeDateStamp members, plus padding that gets these members to the same offsets as in the true structure.

LDR_DATA_TABLE_ENTRY* GetLdrDatTableEntryInternal( const wchar_t* modName )
{
	LDR_DATA_TABLE_ENTRY* modLdtEntry = nullptr;

	//!Getting PEB structure using NtQueryInformationProcess() function
	PEB* peb = getPEBFileLess();

	//!Using the PEB structure to get member Ldr( PEB_LDR_DATA) structure
	//! PEB_LDR_DATA structure in turn contains the LIST_ENTRY linked list structure
	//! LIST_ENTRY structure is named InMemoryOrderModuleList which contains list of loaded modules
	LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

	//?  the links in these lists are not safe to follow while modules might be loaded and unloaded. That this can’t happen at the time can be hard enough to ensure even for the current process.
	//? So we obtain LDR_DATA_TABLE_ENTRY structure WHICH IS MORE STABLE

	LIST_ENTRY current = head;

	//!Parsing the LIST_ENTRY structure to get the required 
	for (auto current = head; current.Flink != &peb->Ldr->InMemoryOrderModuleList; current = *current.Flink)
	{
		//!The CONTAINING_RECORD macro returns the base address of an instance of a structure given the type of the structure and the address of a field within the containing structure.
		//! this is used to return the address of variable 
		LDR_DATA_TABLE_ENTRY* ldtEntry = (LDR_DATA_TABLE_ENTRY*) CONTAINING_RECORD( current.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
		//! full path address needs to be given FOR COMPARISON as it is only defined field in present definition of _LDR_DATA_TABLE_ENTRY
		//! BaseDllName member is nor defined so not showing up
		if (ldtEntry->BaseDllName.Buffer)
		{
			//!BaseDllName.buffer is of wchar_t* so modname has to be of type wchar_t*
			//! also _wcsicmp version of wstring comparison has to be used
			//! //!Note _LDR_DATA_TABLE_ENTRY string fields e.g FullDllName, BaseDllName are of type wchar_t*
			if (_wcsicmp( modName, ldtEntry->BaseDllName.Buffer ) == 0)
			{
				modLdtEntry = ldtEntry;
				break;
			}
		}
	}
	return modLdtEntry; //!returns poniter to LDR_DATA_TABLE_ENTRY structure
}

//!alternative way to find Module address other then GetModuleHandle()
ptrdiff_t FindModuleHandle( const wchar_t* moduleName )
{/*
	size_t newsize = strlen( moduleName ) + 1;
	wchar_t* wcstring = new wchar_t[newsize];
	//convert char* string to wchar_t* string
	size_t convertedChars = 0;
	mbstowcs_s( &convertedChars, wcstring, newsize, moduleName, _TRUNCATE );
	ptrdiff_t moduleBaseAddress = (ptrdiff_t) GetLdrDatTableEntryInternal( wcstring );
	std::wcout << wcstring;
	std::cout << std::hex << moduleBaseAddress;
	//! If not using wstring directly we have to deallocate wcstring gnerated for conversion
	delete[]wcstring; // to deallocate the bufffer
	return moduleBaseAddress;*/

	//If moduleName argument is of wstring type use cancelled instructions
	//x !To convert wstring to  const wchar_t* use member function .c_str() 
	//x return { (ptrdiff_t) (GetLdrDatTableEntryInternal( moduleName.c_str() ))->DllBase };
	
	return { (ptrdiff_t) (GetLdrDatTableEntryInternal( moduleName ))->DllBase }; 
	
}

// main program to parse syscall and dump those

int main()
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) FindModuleHandle( L"ntdll.dll" );
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((LPBYTE) pDosHeader + pDosHeader->e_lfanew);
	//invalid file exit
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return -1;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((LPBYTE) pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pExportDirectory)
		return -1;
	PDWORD pEAT = (PDWORD) ((LPBYTE) pDosHeader + pExportDirectory->AddressOfFunctions);
	PDWORD pENPT = (PDWORD) ((LPBYTE) pDosHeader + pExportDirectory->AddressOfNames);
	//!VIMP:export_name_ordinal_table is array of WORD size ordinals which index directly into pEAT So PWORD
	PWORD pEOT = (PWORD) ((LPBYTE) pDosHeader + pExportDirectory->AddressOfNameOrdinals);
	unsigned char pBuffer[32]{}; // create a null byte char buffer to hold address
	const unsigned char pSigSyscall[4] = { 0x4c,0x8b,0xd1,0xb8 };
	printf( "SYSCALL        ADDRESS        FUNCTION\n" );
	printf( "----------------------------------------------\n" );

	for (size_t i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		memset( &pBuffer, 0, 32 );
		//!gives addrs of function as value ordinal got from index i in pEOT
		PVOID pAddress = (PVOID) ((LPBYTE) pDosHeader + pEAT[pEOT[i]]);
		char* apiName = (char*) pDosHeader + pENPT[i];
		//Copyig the opcodes at the pAddres to pBuffer char array
		memcpy( &pBuffer, pAddress, 32 );
		//invalid address and name check
		if (!pAddress || !apiName)
			break;
		//loop to check the current address matching our signatures
		for (int x = 0; x < sizeof( pSigSyscall ); ++x)
		{
			//!if sig not matching the adress than break current loop(current addres)
			//! Outer loop will start moving for next address chreck
			if (pBuffer[x] != pSigSyscall[x])
				break;
			//if sig are matched till length 4 then syscall found
			if (x == sizeof( pSigSyscall ) - 1)
				printf( " 0x%02x\t %p\t %s \n", pBuffer[4],pAddress,apiName );

		}

	}

	asmSysCaller();
	return 0;
}