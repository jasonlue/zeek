
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek UvPcap)
zeek_plugin_cc(PcapSource.cc Plugin.cc)
#bif_target(pcap.bif)
zeek_plugin_end()
