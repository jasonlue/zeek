// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

extern "C" {
#include <pcap.h>
}

#include <uv.h>

#include <string>
#include "FD_Set.h"
#include "Timer.h"

namespace iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main
 * loop.
 */
class IOSource {
public:
	
	/**
	 * Constructor.
	 *
	 * @param loop The libuv loop to use, if creating a libuv-based iosource;
	 */
	IOSource(uv_loop_t* loop = nullptr) : loop(loop) {}

	/**
	 * Destructor.
	 */
	virtual ~IOSource();

	/**
	 * Returns true if source has nothing ready to process.
	 */
	bool IsIdle() const	{ return idle; }

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const	{ return ! closed; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void Init()	{ }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done();

	/**
	 * Returns select'able file descriptors for this source. Leaves the
	 * passed values untouched if not available.
	 *
	 * @param read Pointer to container where to insert a read descriptor.
	 *
	 * @param write Pointer to container where to insert a write descriptor.
	 *
	 * @param except Pointer to container where to insert a except descriptor.
	 */
	virtual void GetFds(FD_Set* read, FD_Set* write, FD_Set* except) {}

	/**
	 * Returns the timestamp (in \a global network time) associated with
	 * next data item from this source.  If the source wants the data
	 * item to be processed with a local network time, it sets the
	 * argument accordingly.
	 *
	 * This method will be called only when either IsIdle() returns
	 * false, or select() on one of the fds returned by GetFDs()
	 * indicates that there's data to process.
	 *
	 * Must be overridden by derived classes.
	 *
	 * @param network_time A pointer to store the \a local network time
	 * associated with the next item (as opposed to global network time).
	 *
	 * @return The global network time of the next entry, or a value
	 * smaller than zero if none is available currently.
	 */
	virtual double NextTimestamp(double* network_time) { return 0.0; }

	/**
	 * Processes and consumes next data item.
	 *
	 * This method will be called only when either IsIdle() returns
	 * false, or select() on one of the fds returned by GetFDs()
	 * indicates that there's data to process.
	 *
	 * Must be overridden by derived classes.
	 */
	virtual void Process() = 0;

	/**
	 * Returns the tag of the timer manager associated with the last
	 * proceseed data item.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The tag, or null for the global timer manager.
	 * 
	 */
	virtual TimerMgr::Tag* GetCurrentTag()	{ return nullptr; }

	/**
	 * Returns a descriptual tag representing the source for debugging.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;
	
	/**
	 * Cleans up the memory used for the uv handle. Called by the callback
	 * for uv_close() during shutdown.
	 */
	void Cleanup();

	static IOSource* GetSource(const uv_idle_t* callback_handle);
	static IOSource* GetSource(const uv_poll_t* callback_handle);

protected:

	/**
	 * Adds a callback method to the loop, based on what type of handler. One of
	 * these methods must be called by a child class, or the source will not be
	 * handled during the loop.
	 */
	bool Start(uv_idle_cb callback);
	bool Start(uv_poll_cb callback, int fd);

	/*
	 * Callback for derived classes to call when they have gone dry
	 * temporarily.
	 *
	 * @param is_idle True if the source is idle currently.
	 */
	void SetIdle(bool is_idle)	{ idle = is_idle; }

	/*
	 * Callback for derived class to call when they have shutdown.
	 *
	 * @param is_closed True if the source is now closed.
	 */
	void SetClosed(bool is_closed)	{ closed = is_closed; }

	uv_loop_t* loop = nullptr;

private:

	uv_handle_t* handle = nullptr;
	bool idle = false;
	bool closed = false;
};

}
