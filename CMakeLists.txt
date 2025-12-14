cmake_minimum_required(VERSION 3.10)
project(WifiScanner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)

add_executable(wifi_scanner
    src/main.c
    src/netlink.c
    src/scan.c
)

target_include_directories(wifi_scanner PRIVATE
    ${LIBNL_INCLUDE_DIRS}
)

target_link_libraries(wifi_scanner
    ${LIBNL_LIBRARIES}
)
