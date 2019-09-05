#include "PktSrc.h"

#include "util.h"
#include "Net.h"
#include "Sessions.h"

using namespace uvsource;

PktSrc::PktSrc(uv_loop_t* loop, const std::string& path, bool is_live) : UVIOSource(loop)
	{
	props.path = path;
	props.is_live = is_live;
	}

const std::string& PktSrc::Path() const
	{
	static std::string not_open("not open");
	return IsOpen() ? props.path : not_open;
	}

const char* PktSrc::ErrorMsg() const
	{
	return errbuf.size() ? errbuf.c_str() : 0;
	}

int PktSrc::LinkType() const
	{
	return IsOpen() ? props.link_type : -1;
	}

uint32_t PktSrc::Netmask() const
	{
	return IsOpen() ? props.netmask : NETMASK_UNKNOWN;
	}

bool PktSrc::IsError() const
	{
	return ErrorMsg();
	}

bool PktSrc::IsLive() const
	{
	return props.is_live;
	}

double PktSrc::CurrentPacketTimestamp()
	{
	return current_pseudo;
	}

double PktSrc::CurrentPacketWallClock()
	{
	// We stop time when we are suspended.
	if ( net_is_processing_suspended() )
		current_wallclock = current_time(true);

	return current_wallclock;
	}

void PktSrc::Opened()
	{
	// TODO
	// if ( Packet::GetLinkHeaderSize(arg_props.link_type) < 0 )
	//	{
	//	char buf[512];
	//	safe_snprintf(buf, sizeof(buf),
	//		 "unknown data link type 0x%x", arg_props.link_type);
	//	Error(buf);
	//	Close();
	//	return;
	//	}

	// TODO
	// if ( ! PrecompileFilter(0, "") || ! SetFilter(0) )
	//	{
	//	Close();
	//	return;
	//	}

	if ( props.is_live )
		Info(fmt("listening on %s\n", props.path.c_str()));

	DBG_LOG(DBG_PKTIO, "Opened source %s", props.path.c_str());
	}

void PktSrc::Closed()
	{
	DBG_LOG(DBG_PKTIO, "Closed source %s", props.path.c_str());
	}

void PktSrc::Error(const std::string& msg)
	{
	// We don't report this immediately, Bro will ask us for the error
	// once it notices we aren't open.
	errbuf = msg;
	DBG_LOG(DBG_PKTIO, "Error with source %s: %s",
		IsOpen() ? props.path.c_str() : "<not open>",
		msg.c_str());
	}

void PktSrc::Info(const std::string& msg)
	{
	reporter->Info("%s", msg.c_str());
	}

void PktSrc::Weird(const std::string& msg, const Packet* p)
	{
	sessions->Weird(msg.c_str(), p, 0);
	}

void PktSrc::InternalError(const std::string& msg)
	{
	reporter->InternalError("%s", msg.c_str());
	}

void PktSrc::ContinueAfterSuspend()
	{
	current_wallclock = current_time(true);
	}

double PktSrc::CheckPseudoTime()
	{
	if ( ! IsOpen() || ! have_packet )
		return 0;

	double pseudo_time = current_packet.time - first_timestamp;
	double ct = (current_time(true) - first_wallclock) * pseudo_realtime;

	return pseudo_time <= ct ? bro_start_time + pseudo_time : 0;
	}

/**
 * Processes and consumes the next data item. This should be called during
 * the callback for the handles whenever new data is received.
 */
void PktSrc::Process()
	{
	if ( ! IsOpen() || ! have_packet )
		return;

	if ( current_packet.Layer2Valid() )
		{
		if ( pseudo_realtime > 0.0 )
			{
			current_pseudo = CheckPseudoTime();
			// TODO : pass the packet to somewhere to be actually dealt with
			if ( ! first_wallclock )
				first_wallclock = current_time(true);
			}
		else
			{
			// TODO : pass the packet to somewhere to be actually dealt with
			printf("processing not as pseudo\n");
			}
		}

	have_packet = false;

	// TODO: the old code has a method to tell the actual source code that we're
	// done with the packet. do we need to keep that?
	// DoneWithPacket();
	}
