cmake_minimum_required(VERSION 3.12)
project(sshkey LANGUAGES C)

option(ENABLE_TESTS "Build tests" OFF)

find_package(OpenSSL 3.0 REQUIRED)

add_library(sshkey STATIC
    src/sshkey.h
    src/sshkey.c)

target_include_directories(sshkey PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(sshkey PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

add_executable(convert
    test/convert.c)

if(ENABLE_TESTS)
    enable_testing()

    target_include_directories(convert PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(convert sshkey)

    find_program(BASH_PROGRAM bash)
    if(BASH_PROGRAM)
        add_test(mytest ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/test/test.sh)
    endif()
endif()
