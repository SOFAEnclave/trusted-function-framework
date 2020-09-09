set(TOP_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

add_subdirectory(trusted)
add_subdirectory(untrusted)
add_subdirectory(untrusted/challenger)
