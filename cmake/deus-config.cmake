if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 3.0)
   message(FATAL_ERROR "CMake >= 3.0.0 required")
endif()
cmake_policy(PUSH)
cmake_policy(VERSION 3.0...3.28)
set(CMAKE_IMPORT_FILE_VERSION 1)

get_filename_component(_IMPORT_PREFIX "${CMAKE_CURRENT_LIST_FILE}" PATH)
get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" PATH)
if(_IMPORT_PREFIX STREQUAL "/")
  set(_IMPORT_PREFIX "")
endif()

if(NOT TARGET deus::deus)
  add_library(deus::deus INTERFACE IMPORTED)
  set_target_properties(deus::deus PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include"
    INTERFACE_COMPILE_DEFINITIONS "UMDF_USING_NTSTATUS"
    INTERFACE_COMPILE_FEATURES "cxx_std_23"
    INTERFACE_LINK_LIBRARIES "ntdll")
endif()

set(_IMPORT_PREFIX)

set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)
