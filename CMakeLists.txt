cmake_minimum_required(VERSION 3.16)

project(MemLib VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(deps)

add_library(MemLib STATIC)
add_library(MemLib::MemLib ALIAS MemLib)

target_compile_features(MemLib PUBLIC cxx_std_23)

target_include_directories(MemLib
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/code/public>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

set(MEMLIB_PUBLIC_HEADERS
    code/public/memlib.hpp
    code/public/memlib/hook.hpp
    code/public/memlib/macros.hpp
    code/public/memlib/memory.hpp
    code/public/memlib/os.hpp
    code/public/memlib/re_helper_macros.hpp
    code/public/memlib/scanner.hpp
    code/public/memlib/thread.hpp
)

set(MEMLIB_PRIVATE_SOURCES
    code/private/internal.hpp
    code/private/hook.cpp
    code/private/memlib.cpp
    code/private/memory.cpp
    code/private/scanner.cpp
    code/private/thread.cpp
)

if (WIN32)
  list(APPEND MEMLIB_PRIVATE_SOURCES
    code/private/os/windows.cpp
  )
elseif(UNIX)
  list(APPEND MEMLIB_PRIVATE_SOURCES
    code/private/os/linux.cpp
  )
endif()

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/code/public"  PREFIX "Public"  FILES ${MEMLIB_PUBLIC_HEADERS})
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/code/private" PREFIX "Private" FILES ${MEMLIB_PRIVATE_SOURCES})

# Sources: list explicitly (example placeholders)
target_sources(MemLib
  PRIVATE
    ${MEMLIB_PUBLIC_HEADERS}
    ${MEMLIB_PRIVATE_SOURCES}
)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if (WIN32)
  target_compile_definitions(MemLib PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

target_link_libraries(MemLib
  PRIVATE
    Zycore
    Zydis
    safetyhook::safetyhook
)

if (MSVC)
  target_compile_options(MemLib PRIVATE /W4 /permissive-)
else()
  target_compile_options(MemLib PRIVATE -Wall -Wextra -Wpedantic -fPIC)
endif()

# -----------------------
# Install + export package
# -----------------------
install(TARGETS MemLib
  EXPORT MemLibTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/code/public/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp" PATTERN "*.inl"
)

install(EXPORT MemLibTargets
  FILE MemLibTargets.cmake
  NAMESPACE MemLib::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MemLib
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/MemLibConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/MemLibConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MemLib
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/MemLibConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/MemLibConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/MemLibConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MemLib
)
