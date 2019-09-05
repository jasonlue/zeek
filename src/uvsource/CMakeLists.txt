include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(pcap)

set(uvsource_SRCS
  UVIOSource.cc
  PktSrc.cc
  Component.cc
  Manager.cc
)

bro_add_subdir_library(uvsource ${uvsource_SRCS})
add_dependencies(bro_uvsource generate_outputs)
