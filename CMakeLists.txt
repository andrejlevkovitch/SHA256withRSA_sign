# cmake
cmake_minimum_required(VERSION 3.12)

project(SHA256withRSA)

include(cmake/build.cmake)

find_package(OpenSSL REQUIRED)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LuaJit REQUIRED)

set(CMAKE_SHARED_LIBRARY_PREFIX "")

add_library(${PROJECT_NAME} lua_SHA256withRSA.cpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME} PRIVATE
  OpenSSL::SSL
  ${LUAJIT_LIBRARIES}
  )
target_compile_options(${PROJECT_NAME} PRIVATE -fPIC)
target_include_directories(${PROJECT_NAME} PRIVATE
  ${LUAJIT_INCLUDE_DIRS})

add_executable(sign main.cpp)
target_compile_features(sign PRIVATE cxx_std_17)
target_link_libraries(sign PRIVATE
  OpenSSL::SSL
  stdc++fs
  )
