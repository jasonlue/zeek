// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <uv.h>
#include <memory>

#include "Timer.h"

namespace uvsource {

/**
 * Interface class for components providing/consuming data inside Bro, using libuv.
 */
class UVIOSource {

public:

	/**
	 * Constructor.
	 */
	UVIOSource(uv_loop_t* loop) : loop(loop) {}

	/**
	 * Destructor.
	 */
	virtual ~UVIOSource();

	UVIOSource(const UVIOSource&) = default;
	UVIOSource(UVIOSource&&) = default;
	UVIOSource& operator=(const UVIOSource&) = default;
	UVIOSource& operator=(UVIOSource&&) = default;

	/**
	 * Starts the source, adding it to the event loop.
	 */
	virtual void Start() = 0;

	/**
	 * Shuts down the source and removes the handle from the respective uv loop.
	 * This must be called by child classes in order to properly clean up.
	 */
	virtual void Stop();

	/**
	 * Returns a descriptive tag representing the source for debugging.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const { return ! closed; }

	/**
	 * Cleans up the memory used for the uv handle. Called by the callback for
	 * uv_close during shutdown.
	 */
	void Cleanup();

	/**
	 * Processes and consumes the next data item. This should be called during
	 * the callback for the handles whenever new data is received.
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

	static UVIOSource* GetSource(const uv_idle_t* callback_handle);
	static UVIOSource* GetSource(const uv_poll_t* callback_handle);

protected:

	/**
	 * Adds a callback method to the loop, based on what type of handler. One of
	 * these methods must be called by a child class, or the source will not be
	 * handled during the loop.
	 */
	bool Start(uv_idle_cb callback);
	bool Start(uv_poll_cb callback, int fd);

	uv_loop_t* loop = nullptr;

private:

	uv_handle_t* handle = nullptr;
	bool closed = false;
};

using UVIOSourcePtr = std::shared_ptr<UVIOSource>;

}
