cmake_minimum_required(VERSION 3.16)
project(Il2CppDumperSwitchPort CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(switch_il2cpp_metadata
    src/main.cpp
    src/MetadataFile.cpp
    src/ElfImage.cpp
    src/RegistrationFinder.cpp
    src/RuntimeTypeSystem.cpp
)

target_include_directories(switch_il2cpp_metadata
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(switch_il2cpp_metadata PRIVATE /W4)
else()
    target_compile_options(switch_il2cpp_metadata PRIVATE -Wall -Wextra -Wpedantic)
endif()
