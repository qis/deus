cmake_minimum_required(VERSION 3.23 FATAL_ERROR)
project(deus DESCRIPTION "DEUS" VERSION 0.1.0 LANGUAGES CXX)

# Conan
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Dependencies
find_package(Boost REQUIRED COMPONENTS headers)
find_package(TBB REQUIRED COMPONENTS tbb)
find_package(WDK REQUIRED)

foreach(dir ${TBB_LIB_DIRS})
  get_filename_component(dir ${dir} DIRECTORY)
  foreach(lib ${TBB_LIBRARY_LIST})
    if(EXISTS ${dir}/bin/${lib}.dll)
      if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${lib}.dll)
        file(COPY ${dir}/bin/${lib}.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
      endif()
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${lib}.dll DESTINATION bin)
    endif()
  endforeach()
endforeach()

# Driver
wdk_add_driver(driver KMDF 1.15 WINVER 0x0A00 src/deus.h src/deus.cxx)
set_target_properties(driver PROPERTIES OUTPUT_NAME deus)
target_compile_definitions(driver PRIVATE DEUS_DRIVER NOMINMAX BOOST_DISABLE_ASSERTS)
target_compile_features(driver PRIVATE cxx_std_23)

target_include_directories(driver PRIVATE src ${Boost_INCLUDE_DIRS})

set_target_properties(driver PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/sys
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/sys
  PDB_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/sys)

install(TARGETS driver RUNTIME DESTINATION bin)

# Library
add_library(deus SHARED src/deus.h src/deus.hpp src/deus.cpp src/main.rc)
target_compile_definitions(deus PRIVATE DEUS_EXPORTS NOMINMAX)
target_compile_features(deus PRIVATE cxx_std_23)

target_include_directories(deus PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>)

target_link_libraries(deus PUBLIC Boost::headers TBB::tbb)

set_target_properties(deus PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
  PDB_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

add_dependencies(deus driver)

install(TARGETS deus EXPORT ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib)

install(FILES $<TARGET_PDB_FILE:deus> DESTINATION bin OPTIONAL)
install(FILES src/deus.h src/deus.hpp DESTINATION include)

# Executable
add_executable(main src/main.cpp src/main.manifest src/main.rc)
set_target_properties(main PROPERTIES OUTPUT_NAME deus)
target_compile_definitions(main PRIVATE NOMINMAX)
target_compile_features(main PRIVATE cxx_std_23)
target_link_options(main PRIVATE /manifest:no)

target_link_libraries(main PRIVATE deus)

install(TARGETS main RUNTIME DESTINATION bin)

# Export
install(EXPORT ${PROJECT_NAME} FILE ${PROJECT_NAME}-targets.cmake
  NAMESPACE ${PROJECT_NAME}:: DESTINATION lib/cmake/${PROJECT_NAME})

include(CMakePackageConfigHelpers)
configure_package_config_file(res/config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
  INSTALL_DESTINATION lib/cmake/${PROJECT_NAME})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
  DESTINATION lib/cmake/${PROJECT_NAME})

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
