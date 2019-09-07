#pragma once

#include <string>

#include "iosource/Packet.h"
#include "iosource/IOSource.h"

namespace uvsource {

class PktSrc : public iosource::IOSource
	{
public:
	static const int NETMASK_UNKNOWN = 0xffffffff;

	/**
	 * Struct for returning statistics on a packet source.
	 */
	struct Stats {
		/**
		 * Packets received by source after filtering (w/o drops).
		 */
		uint64_t received;

		/**
		 * Packets dropped by source.
		 */
		uint64_t dropped;	// pkts dropped

		/**
		 * Total number of packets on link before filtering.
		 * Optional, can be left unset if not available.
		 */
		uint64_t link;

		/**
		  * Bytes received by source after filtering (w/o drops).
		*/
		uint64_t bytes_received;

		Stats()	{ received = dropped = link = bytes_received = 0; }
	};

	PktSrc(uv_loop_t* loop, const std::string& path, bool is_live);

	PktSrc(const PktSrc&) = default;
	PktSrc(PktSrc&&) = default;
	PktSrc& operator=(const PktSrc&) = default;
	PktSrc& operator=(PktSrc&&) = default;

	virtual ~PktSrc() = default;

	/**
	 * Returns the path associated with the source. This is the interface
	 * name for live source, and a filename for offline sources.
	 */
	const std::string& Path() const;

	/**
	 * Returns true if this is a live source.
	 */
	bool IsLive() const;

	/**
	 * Returns the link type of the source.
	 */
	int LinkType() const;

	/**
	 * Returns the netmask associated with the source, or \c
	 * NETMASK_UNKNOWN if unknown.
	 */
	uint32_t Netmask() const;

	/**
	 * Returns true if the source has flagged an error.
	 */
	bool IsError() const;

	/**
	 * If the source encountered an error, returns a corresponding error
	 * message. Returns an empty string otherwise.
	 */
	const char* ErrorMsg() const;

	/**
	 * In pseudo-realtime mode, returns the logical timestamp of the
	 * current packet. Undefined if not running pseudo-realtime mode.
	 */
	double CurrentPacketTimestamp();

	/**
	 * In pseudo-realtime mode, returns the wall clock time associated
	 * with current packet. Undefined if not running pseudo-realtime
	 * mode.
	 */
	double CurrentPacketWallClock();

	/**
	 * Signals packet source that processing is going to be continued
	 * after previous suspension.
	 */
	void ContinueAfterSuspend();

	// PktSrc interface for derived classes to implement.

	/**
	 * Called by the manager system to initialize and start the source.
	 */
	virtual void Init() override {}

protected:

	friend class Manager;

	/**
	 * Structure to pass back information about the packet source to the
	 * base class. Derived class pass an instance of this to \a Opened().
	 */
	struct Properties {
		/**
		 * The path associated with the source. This is the interface
		 * name for live source, and a filename for offline sources.
		 */
		std::string path;

		/**
		 * The link type for packets from this source.
		 */
		int link_type = -1;

		/**
		 * Returns the netmask associated with the source, or \c
		 * NETMASK_UNKNOWN if unknown.
		 */
		uint32_t netmask = NETMASK_UNKNOWN;

		/**
		 * True if the source is reading live inout, false for
		 * working offline.
		 */
		bool is_live = false;
	};

	/**
	 * Called from the implementations of \a Open() to signal that the
	 * source has been successully opened.
	 */
	void Opened();

	/**
	 * Called from the implementations of \a Close() to signal that the
	 * source has been closed.
	 */
	void Closed();

	/**
	 * Can be called from derived classes to send an informational
	 * message to the user.
	 *
	 * @param msg The message to pass on.
	 */
	void Info(const std::string& msg);

	/**
	 * Can be called from derived classes to flag send an error.
	 *
	 * @param msg The message going with the error.
	 */
	void Error(const std::string& msg);

	/**
	 * Can be called from derived classes to flag a "weird" situation.
	 *
	 * @param msg The message to pass on.
	 *
	 * @param pkt The packet associated with the weird, or null if none.
	 */
	void Weird(const std::string& msg, const Packet* pkt);

	/**
	 * Can be called from derived classes to flag an internal error,
	 * which will abort execution.
	 *
	 * @param msg The message to pass on.
	 */
	void InternalError(const std::string& msg);

	// Checks if the current packet has a pseudo-time <= current_time. If
	// yes, returns pseudo-time, otherwise 0.
	double CheckPseudoTime();

	/**
	 * Processes and consumes the next data item. This should be called during
	 * the callback for the handles whenever new data is received.
	 */
	virtual void Process() override;

	Properties props;

	bool have_packet = false;
	Packet current_packet;
	Stats stats;

private:

	virtual const char* Tag() override { return "PktSrc-UV"; }

	// Only set in pseudo-realtime mode.
	double first_timestamp = 0.0;
	double first_wallclock = 0.0;
	double current_wallclock = 0.0;
	double current_pseudo = 0.0;
	double next_sync_point = 0.0; // For trace synchronziation in pseudo-realtime

	std::string errbuf;
	};

}
