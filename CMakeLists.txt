cmake_minimum_required(VERSION 3.10)

project(router C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_GENERATOR_TOOLSET "v141_xp")

include_directories(libs/WpdPack/Include)
link_directories(libs/WpdPack/Lib)

set(PCAP_LIBS wpcap Packet)

add_executable(router WIN32 main.c router.c router.h)
target_link_libraries(router ${PCAP_LIBS})
target_link_options(router PRIVATE /SUBSYSTEM:CONSOLE,5.01)