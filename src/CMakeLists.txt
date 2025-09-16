cmake_minimum_required(VERSION 3.31)
#project(desfire)

set(CMAKE_CXX_STANDARD 20)

add_executable(mifareinfo
        mifareinfo.cpp
        ScopeGuard.cpp ScopeGuard.h
        exceptions.cpp exceptions.h
        freefare_errorcodes.h
        keyfile.h)
target_link_libraries(mifareinfo libfreefare.so libnfc.so)

add_executable(read
        read.cpp
        ScopeGuard.cpp ScopeGuard.h
        exceptions.cpp exceptions.h
        freefare_errorcodes.h
        keyfile.h)
target_link_libraries(read libfreefare.so libnfc.so docopt)

add_executable(install-application
        install-application.cpp
        ScopeGuard.cpp ScopeGuard.h
        exceptions.cpp exceptions.h
        freefare_errorcodes.h
        keyfile.h
)
target_link_libraries(install-application libfreefare.so libnfc.so)

add_executable(nfcurl nfc.cpp)
target_link_libraries(nfcurl libfreefare.so libnfc.so)

add_executable(format
        format.cpp
        ScopeGuard.cpp ScopeGuard.h
        exceptions.cpp exceptions.h
        freefare_errorcodes.h
        keyfile.h
)
target_link_libraries(format libfreefare.so libnfc.so)

#configure_file(keys/picc.master.key keys/picc.master.key COPYONLY)
#configure_file(keys/app1.master.key keys/app1.master.key COPYONLY)
#configure_file(keys/app1.rw1.key keys/app1.rw1.key COPYONLY)

#include_directories(PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../docopt.cpp)
#target_include_directories(nfcurl PUBLIC
#        ${CMAKE_CURRENT_SOURCE_DIR}/NDEF
#)

#add_subdirectory(docopt.cpp)
