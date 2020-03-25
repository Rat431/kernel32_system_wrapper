/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.

	Notes:
	Define wrapper internal functions and some MACROs.
*/

#pragma once
#include "kernel32_exports.h"

#define NTDLL_MOD L"ntdll.dll"
#define KERNEL32_MOD L"kernel32.dll"
#define KERNELBASE_MOD L"kernelbase.dll"

#define API_FGET "GetProcAddress"
#define NEEDED_APIS 1

typedef void* (_stdcall* VGetProcessAddress)(void*, const char*);

namespace KernelF
{
	static int StringCmp(const char* St1, const char* St2);
	static size GetStringLength(const char* String);
	static void StringCopy(char* pOutString, const char* pIn);
	static int StringCmpW(const wchar_t* St1, const wchar_t* St2);
	static size GetStringLengthW(const wchar_t* String);
	static void StringCopyW(wchar_t* pOutString, const wchar_t* pIn);

	static void LoadOriginalFunctions(void* hModule);
	static void* HGetModBase(const wchar_t* pMName);
	static void* HGetFunctionAddr(void* hModule, const char* pFName);
	static bool InitAPIsFuncs(void* hKernel);
	
	// init
	void InitWrapper(void* hMMod);
}