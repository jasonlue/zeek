#pragma once

#include <pcap.h>
#include <string>

#include "PktSrc.h"

namespace uvsource {
namespace pcap {

class PcapSource : public uvsource::PktSrc
	{
public:
	PcapSource(uv_loop_t* loop, const std::string& path, bool is_live);
	~PcapSource() = default;

	virtual void Start() final;
	virtual void Stop() final;
	void GetPacket();

	static PktSrc* Instantiate(uv_loop_t* loop, const std::string& path, bool is_live);

private:

	bool OpenLive();
	bool OpenFile();
	
	void SetHdrSize();
	void PcapError(const std::string& where = "");

	pcap_t* pd = nullptr;

	struct pcap_pkthdr current_hdr;
	struct pcap_pkthdr last_hdr;
	const u_char* last_data = nullptr;
	};

}
}
