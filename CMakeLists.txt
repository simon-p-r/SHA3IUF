project (sha3-iuf C)

cmake_minimum_required (VERSION 3.10)

option (BUILD_SHARED_LIBS "shared/static libs" OFF)
option(BUILD_TESTS "tests?" OFF)


add_library(sha3 sha3.c)

if (BUILD_SHARED_LIBS)
    target_compile_definitions(sha3
    INTERFACE
        USING_SHA3_SHARED=1
    PRIVATE
        BUILDING_SHA3_SHARED=1
    )
endif()

set(sum_sources sha3sum.c)
if(WIN32)
   list(APPEND sum_sources win32/mman.c)
endif()


add_executable(sha3sum ${sum_sources})
target_link_libraries(sha3sum sha3)

if (BUILD_TESTS)
    enable_testing ()
    add_executable (test_sha3 sha3test.c)
    target_link_libraries (test_sha3 sha3)
    add_test (NAME test_sha3 COMMAND test_sha3${CMAKE_EXECUTABLE_SUFFIX})
endif()

