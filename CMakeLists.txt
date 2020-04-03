# cmake
cmake_minimum_required(VERSION 3.12)

project(SHA256withRSA)

include(build.cmake)

find_package(OpenSSL REQUIRED)
find_package(Lua 5.1 REQUIRED)

set(CMAKE_SHARED_LIBRARY_PREFIX "")

add_library(${PROJECT_NAME} lua_SHA256withRSA.cpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME} PRIVATE
  OpenSSL::SSL
  ${LUA_LIBRARIES}
  )
target_include_directories(${PROJECT_NAME} PRIVATE
  ${LUA_INCLUDE_DIR})

add_executable(sign main.cpp)
target_compile_features(sign PRIVATE cxx_std_17)
target_link_libraries(sign PRIVATE
  OpenSSL::SSL
  stdc++fs
  )
