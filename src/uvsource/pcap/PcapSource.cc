#include "PcapSource.h"
#include "zeek-config.h"
#include "util.h"
#include "Reporter.h"

using namespace uvsource::pcap;

// TODO: these should be from BifConst::Pcap
const int snaplen = 9216;
const int bufsize = 128;

void file_callback(uv_idle_t* handle)
	{
	PcapSource* source = reinterpret_cast<PcapSource*>(uvsource::UVIOSource::GetSource(handle));
	source->GetPacket();
	}

void live_callback(uv_poll_t* handle, int status, int error)
	{
	PcapSource* source = reinterpret_cast<PcapSource*>(uvsource::UVIOSource::GetSource(handle));
	source->GetPacket();
	}

PcapSource::PcapSource(uv_loop_t* loop, const std::string& path, bool is_live) :
	PktSrc(loop, path, is_live)
	{
	memset(&current_hdr, 0, sizeof(current_hdr));
	memset(&last_hdr, 0, sizeof(last_hdr));
	}

bool PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	// Determine interface if not specified.
	if ( props.path.empty() )
		{
		pcap_if_t* devs = nullptr;

		if ( pcap_findalldevs(&devs, errbuf) < 0 )
			{
			Error(fmt("pcap_findalldevs: %s\n", errbuf));
			return false;
			}

		if ( devs )
			{
			props.path = devs->name;
			pcap_freealldevs(devs);

			if ( props.path.empty() )
				{
				Error(fmt("pcap_findalldevs: empty device name\n"));
				return false;
				}
			}
		else
			{
			Error(fmt("pcap_findalldevs: no devices found\n"));
			return false;
			}
		}

	// Determine network and netmask.
	uint32_t net;
	if ( pcap_lookupnet(props.path.c_str(), &net, &props.netmask, errbuf) < 0 )
		{
		// ### The lookup can fail if no address is assigned to
		// the interface; and libpcap doesn't have any useful notion
		// of error codes, just error std::strings - how bogus - so we
		// just kludge around the error :-(.
		// sprintf(errbuf, "pcap_lookupnet %s", errbuf);
		// return false;
		props.netmask = 0xffffff00;
		}

#ifdef PCAP_NETMASK_UNKNOWN
	// Defined in libpcap >= 1.1.1
	if ( props.netmask == PCAP_NETMASK_UNKNOWN )
		props.netmask = PktSrc::NETMASK_UNKNOWN;
#endif

	pd = pcap_create(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		PcapError("pcap_create");
		return false;
		}

	if ( pcap_set_snaplen(pd, snaplen) )
		{
		PcapError("pcap_set_snaplen");
		return false;
		}

	if ( pcap_set_promisc(pd, 1) )
		{
		PcapError("pcap_set_promisc");
		return false;
		}

	// We use the smallest time-out possible to return false almost immediately
	// if no packets are available. (We can't use set_nonblocking() as
	// it's broken on FreeBSD: even when select() indicates that we can
	// read something, we may get nothing if the store buffer hasn't
	// filled up yet.)
	//
	// TODO: The comment about FreeBSD is pretty old and may not apply
	// anymore these days.
	if ( pcap_set_timeout(pd, 1) )
		{
		PcapError("pcap_set_timeout");
		return false;
		}

	if ( pcap_set_buffer_size(pd, bufsize * 1024 * 1024) )
		{
		PcapError("pcap_set_buffer_size");
		return false;
		}

	if ( pcap_activate(pd) )
		{
		PcapError("pcap_activate");
		return false;
		}

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return false;
		}
#endif

#ifdef HAVE_PCAP_INT_H
	Info(fmt("pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize));
#endif

	SetHdrSize();

	if ( ! pd )
		// Was closed, couldn't get header size.
		return false;

	props.is_live = true;

	// Tell the UV bits to add this source to the loop
	return uvsource::UVIOSource::Start(live_callback, pcap_fileno(pd));
	}

bool PcapSource::OpenFile()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	pd = pcap_open_offline(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		Error(fmt("%s\n", errbuf));
		return false;
		}

	SetHdrSize();

	if ( ! pd )
		// Was closed, unknown link layer type.
		return false;

	props.is_live = false;

	// Tell the UV bits to add this source to the loop
	return uvsource::UVIOSource::Start(file_callback);
	}

void PcapSource::Start()
	{
	bool result = props.is_live ? OpenLive() : OpenFile();
	
	if ( result )
		Opened();
	else
		Stop();
	}

void PcapSource::GetPacket()
	{
	if ( ! pd )
		// TODO: failure case? why are we still in the loop if the pcap is closed?
		return;

	// If we have an existing packet and it works for the current psuedo-time, pass it
	// off for processing and return. Don't get a new packet right now.
	if ( CheckPseudoTime() > 0.0 )
		{
		printf("already had a packet, passing to process\n");
		Process();
		return;
		}

	// We didn't have an existing packet already so get one from pcap.
	const u_char* data = pcap_next(pd, &current_hdr);

	if ( ! data )
		{
		// Source has gone dry.  If it's a network interface, this just means
		// it's timed out. If it's a file, though, then the file has been
		// exhausted.
		if ( ! props.is_live )
			Stop();

		return;
		}

	printf("got packet\n");
	current_packet.Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

	if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
		{
		Weird("empty_pcap_header", &current_packet);
		return;
		}
	
	last_hdr = current_hdr;
	last_data = data;
	++stats.received;
	stats.bytes_received += current_hdr.len;

	have_packet = true;

	// Now that we have a packet again, repeat the check we started with to see if we need
	// to process this new packet.
	if ( CheckPseudoTime() > 0.0 )
		Process();
	}

void PcapSource::Stop()
	{
	if ( ! pd )
		return;

	uvsource::UVIOSource::Stop();

	pcap_close(pd);
	pd = nullptr;

	Closed();
	}

void PcapSource::SetHdrSize()
	{
	if ( ! pd )
		return;

	props.link_type = pcap_datalink(pd);
	}

void PcapSource::PcapError(const std::string& where)
	{
	std::string location;

	if ( ! where.empty() )
		location = fmt(" (%s)", where.c_str());

	if ( pd )
		Error(fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(fmt("pcap_error: not open%s", location.c_str()));

	Stop();
	}

uvsource::PktSrc* PcapSource::Instantiate(uv_loop_t* loop, const std::string& path, bool is_live)
	{
	return new PcapSource(loop, path, is_live);
	}
