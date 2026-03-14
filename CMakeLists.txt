cmake_minimum_required(VERSION 3.20)
project(libhttp3 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(msquic CONFIG REQUIRED)

add_library(http3 STATIC
    src/http3_varint.cpp
    src/http3_frame.cpp
    src/http3_qpack.cpp
    src/http3_server.cpp
    src/http3_client.cpp
    src/http3_webtransport.cpp      # ← NEW
)

target_include_directories(http3
    PUBLIC include
)

target_link_libraries(http3 PUBLIC msquic)

if(WIN32)
    target_link_libraries(http3 PUBLIC ws2_32)
endif()

foreach(ex server client webtransport_server webtransport_client)
    add_executable(h3_${ex} examples/${ex}.cpp)
    target_link_libraries(h3_${ex} PRIVATE http3)
    if(WIN32)
        add_custom_command(TARGET h3_${ex} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:msquic> $<TARGET_FILE_DIR:h3_${ex}>)
    endif()
endforeach()