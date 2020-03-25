# kernel32_system_wrapper
 A mini kernel32 lib wrapper. It can be used to log kernel32 function calls and for many other purposes as well.
 To use this wrapper you need to write your own software/tool that can hook the kernel32 API calls to call the 
 ones that are exported in this project(I suggest to use the IAT hooking method).
 If you want to log any call, you just have to take the API definition on MSDN and implement that to the wrapper, it's pretty easy.
 You can also manage to make this wrapper to wrap other system libraries as long as their modules are loaded in memory.
 For more informations, check the code out.
 
## Build
 - Make sure to not include the kernel32 library and any other dependency on your project. (for Visual Studio /NODEFAULTLIB linker command should be fine)
 - Set the custom EntryPoint to the DllMain function.
 - Disable code generation security check by using this command: /GS-
 - Disable Precompiled Header option.
