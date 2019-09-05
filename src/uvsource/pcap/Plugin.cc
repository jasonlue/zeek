// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "PcapSource.h"
//#include "Dumper.h"

namespace plugin {
namespace Zeek_UvPcap {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::uvsource::PktSrcComponent("UvPcapReader", "uvpcap", ::uvsource::PktSrcComponent::BOTH, ::uvsource::pcap::PcapSource::Instantiate));
//		AddComponent(new ::uvsource::PktDumperComponent("PcapWriter", "uvpcap", ::uvsource::pcap::PcapDumper::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::UvPcap";
		config.description = "Packet acquisition via libpcap";
		return config;
		}
} plugin;

}
}
