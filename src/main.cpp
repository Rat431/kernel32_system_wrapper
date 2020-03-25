/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.

	Notes:
	Implement wrapper DllMain function.
*/

#include "main_system.h"

int _stdcall DllMain(void* hModule, unsigned long  ul_reason_for_call, void* lpReserved)
{
    if (ul_reason_for_call == 1) {
        KernelF::InitWrapper(hModule);
    }
    return 1;
}

