cmake_minimum_required(VERSION 3.28)
project(redis_from_self)

set(CMAKE_CXX_STANDARD 11)
set( CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)


add_executable(server server.cc
        hashtable.h
        avl.cpp
        zset.cpp
        avl.h
        common.h
        hashtable.cpp)
add_executable(client client.cc
        zset.cpp
        avl.h
        common.h
        hashtable.cpp)

add_executable(test_avl
        test_avl.cpp
        zset.cpp
        avl.h
        common.h)
