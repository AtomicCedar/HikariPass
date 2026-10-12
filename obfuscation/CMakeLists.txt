add_library(Hikari SHARED
        FunctionCallObfuscate.cpp
        CryptoUtils.cpp
        BogusControlFlow.cpp
        SubstituteImpl.cpp
        Substitution.cpp
        Flattening.cpp
        LegacyLowerSwitch.cpp
        Utils.cpp
        SplitBasicBlocks.cpp
        AntiDebugging.cpp
        AntiHooking.cpp
        StringEncryption.cpp
        IndirectBranch.cpp
        FunctionWrapper.cpp
        ConstantEncryption.cpp
        Virtualization.cpp
        Obfuscation.cpp
        )
target_include_directories(Hikari PRIVATE ${CMAKE_SOURCE_DIR}/obfuscation)

add_dependencies(Hikari intrinsics_gen LLVMLinker)

# Link against the shared LLVM dylib when the installation ships one.
#
# llvm_map_components_to_libnames() hands back the static component archives
# (libLLVMCore.a, libLLVMSupport.a, ...), which embeds a *second* copy of LLVM
# inside the plugin. The host (clang/opt/rustc) already has LLVM loaded, so the
# duplicate registration makes it abort with:
#
#     CommandLine Error: Option 'x' registered more than once!
#     LLVM ERROR: inconsistency in registered CommandLine options
#
# The dylib target is exported as `LLVM` by LLVMExports.cmake.
if (TARGET LLVM)
    target_link_libraries(Hikari PRIVATE LLVM)
else()
    llvm_map_components_to_libnames(llvm_libs core support irreader linker passes)
    target_link_libraries(Hikari PRIVATE ${llvm_libs})
endif()

# MinGW-specific static link flags. `-lwinpthread` exists only on Windows, so
# this must NOT trigger for plain Linux/macOS GCC builds.
if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties(Hikari PROPERTIES
        LINK_FLAGS "-static -static-libgcc -Wl,-Bstatic,--whole-archive -lwinpthread -lstdc++ -Wl,--no-whole-archive -Wl,-Bdynamic"
    )
endif()
execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        OUTPUT_VARIABLE HIKARI_GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
target_compile_definitions(Hikari PRIVATE "-DGIT_COMMIT_HASH=\"${HIKARI_GIT_COMMIT_HASH}\"")
