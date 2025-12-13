cmake_minimum_required(VERSION 3.10)
project(WifiScanner C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)

include_directories(${LIBNL_INCLUDE_DIRS})
link_directories(${LIBNL_LIBRARY_DIRS})

add_executable(wifi_scanner
    src/main.c
    src/netlink.c
    src/scan.c
)

target_link_libraries(wifi_scanner ${LIBNL_LIBRARIES})
