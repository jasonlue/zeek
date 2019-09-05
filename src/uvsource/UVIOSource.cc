#include "UVIOSource.h"
#include "DebugLogger.h"
#include "util.h"

using namespace uvsource;

UVIOSource::~UVIOSource()
	{
	// If things haven't been stopped yet, stop them. This also covers the case where things
	// are actively stopping.
	if ( handle && uv_is_closing(handle) == 0 )
		Stop();
	}

bool UVIOSource::Start(uv_idle_cb callback)
	{
	uv_idle_t* idle = new uv_idle_t();
	handle = (uv_handle_t*)idle;

	int r = uv_idle_init(loop, idle);
	if ( r != 0 )
		{
		DBG_LOG(DBG_PKTIO, "UVIOSource failed to open init handle: %s", uv_strerror(r));
		Stop();
		return false;
		}

	r = uv_idle_start(idle, callback);
	if ( r != 0 )
		{
		DBG_LOG(DBG_PKTIO, "UVIOSource failed to start init handle: %s", uv_strerror(r));
		Stop();
		return false;
		}

	uv_handle_set_data(reinterpret_cast<uv_handle_t*>(idle), this);

	return true;
	}

bool UVIOSource::Start(uv_poll_cb callback, int fd)
	{
	uv_poll_t* poll = new uv_poll_t();
	handle = (uv_handle_t*)poll;

	int r = uv_poll_init(loop, poll, fd);
	if ( r != 0 )
		{
		DBG_LOG(DBG_PKTIO, "UVIOSource failed to start poll handle: %s", uv_strerror(r));
		Stop();
		return false;
		}

	r = uv_poll_start(poll, UV_READABLE, callback);
	if ( r != 0 )
		{
		DBG_LOG(DBG_PKTIO, "UVIOSource failed to start poll handle: %s", uv_strerror(r));
		Stop();
		return false;
		}

	uv_handle_set_data(reinterpret_cast<uv_handle_t*>(poll), this);

	return true;
	}

static void close_callback(uv_handle_t* handle)
	{
	auto src = reinterpret_cast<UVIOSource*>(uv_handle_get_data(handle));
	src->Cleanup();
	}

void UVIOSource::Cleanup()
	{
	delete handle;
	handle = nullptr;
	}

/**
 * Shuts down the source and removes the handle from the respective uv loop.
 */
void UVIOSource::Stop()
	{
	if ( ! handle )
		return;

	if ( handle.type == UV_IDLE )
		uv_idle_stop(reinterpret_cast<uv_idle_t*>(handle));
	else if ( handle.type == UV_POLL )
		uv_poll_stop(reinterpret_cast<uv_poll_t*>(handle));

	closed = true;

	uv_close(handle, close_callback);
	}

UVIOSource* UVIOSource::GetSource(const uv_idle_t* callback_handle)
	{
	return reinterpret_cast<UVIOSource*>(
		uv_handle_get_data(reinterpret_cast<const uv_handle_t*>(callback_handle)));
	}

UVIOSource* UVIOSource::GetSource(const uv_poll_t* callback_handle)
	{
	return reinterpret_cast<UVIOSource*>(
		uv_handle_get_data(reinterpret_cast<const uv_handle_t*>(callback_handle)));
	}
