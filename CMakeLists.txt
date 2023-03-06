cmake_minimum_required(VERSION 3.23 FATAL_ERROR)
project(deus DESCRIPTION "DEUS" VERSION 0.1.0 LANGUAGES C CXX)

# Conan
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Dependencies
find_package(Boost REQUIRED COMPONENTS headers)
find_package(WDK REQUIRED)

# Driver
wdk_add_driver(driver KMDF 1.15 WINVER 0x0A00 src/deus.h src/deus.cpp)
set_target_properties(driver PROPERTIES OUTPUT_NAME deus)
target_compile_definitions(driver PRIVATE DEUS_DRIVER NOMINMAX BOOST_DISABLE_ASSERTS)
target_compile_features(driver PRIVATE cxx_std_23)

target_include_directories(driver PRIVATE src ${Boost_INCLUDE_DIRS})

set_target_properties(driver PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/driver
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/driver
  PDB_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/driver)

install(TARGETS driver RUNTIME DESTINATION .)

# Library
add_library(deus INTERFACE src/deus.h src/deus.hpp)
target_compile_features(deus INTERFACE cxx_std_23)

target_include_directories(deus INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>)

add_dependencies(deus driver)

install(TARGETS deus EXPORT ${PROJECT_NAME})
install(FILES src/deus.h src/deus.hpp DESTINATION include)

# Executable
add_executable(main WIN32 src/main.cpp src/main.manifest src/main.rc)
set_target_properties(main PROPERTIES OUTPUT_NAME deus)
target_link_options(main PRIVATE /manifest:no)
target_link_libraries(main PRIVATE deus ntdll)

file(GLOB_RECURSE dsefix src/dsefix/*.h src/dsefix/*.c src/dsefix/*.cpp)
target_link_libraries(main PRIVATE legacy_stdio_definitions)
target_include_directories(main PRIVATE src/dsefix)
target_sources(main PRIVATE ${dsefix})

install(TARGETS main RUNTIME DESTINATION .)

# Export
install(EXPORT ${PROJECT_NAME} FILE ${PROJECT_NAME}-config.cmake
  NAMESPACE ${PROJECT_NAME}:: DESTINATION cmake/${PROJECT_NAME})

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
