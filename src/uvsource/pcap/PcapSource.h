#pragma once

#include <pcap.h>
#include <string>

#include "iosource/PktSrc.h"

namespace uvsource {
namespace pcap {

class PcapSource : public iosource::PktSrc
	{
public:
	PcapSource(uv_loop_t* loop, const std::string& path, bool is_live);
	~PcapSource() = default;

	virtual void Open() final;
	virtual void Close() final;

	/**
	 * Called by the libuv callback methods to process a packet from the pcap
	 * interface.
	 */
	void GetPacket();

	static iosource::PktSrc* Instantiate(uv_loop_t* loop, const std::string& path, bool is_live);

protected:

	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;

private:

	// These methods are overridden from PktSrc, but are unused in libuv sources.
	virtual bool ExtractNextPacket(Packet* pkt) override { return false; }
	virtual void DoneWithPacket() override {}

	bool OpenLive();
	bool OpenOffline();
	void PcapError(const std::string& where = "");
	void SetHdrSize();

	Properties props;
	Stats stats;

	pcap_t* pd = nullptr;

	struct pcap_pkthdr current_hdr;
	struct pcap_pkthdr last_hdr;
	const u_char* last_data = nullptr;
	};

}
}
