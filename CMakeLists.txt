cmake_minimum_required(VERSION 3.31)
project(desfire)

include_directories(PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../docopt.cpp)
#target_include_directories(nfcurl PUBLIC
#        ${CMAKE_CURRENT_SOURCE_DIR}/NDEF
#)

add_subdirectory(docopt.cpp)
add_subdirectory(src)
