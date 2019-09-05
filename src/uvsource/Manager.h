#pragma once

#include <uv.h>
#include <vector>
#include <string>

#include "UVIOSource.h"
#include "PktSrc.h"

namespace uvsource {

class Manager {

public:

	static Manager& Get();
	void Init(uv_loop_t* loop);
	void Shutdown();

	void Register(const UVIOSourcePtr& source);

	void FlushClosed();

	/**
	 * Opens a new packet source.
	 *
	 * @param path The interface or file name, as one would give to Bro \c -i.
	 *
	 * @param is_live True if \a path represents a live interface, false
	 * for a file.
	 *
	 * @return The new packet source, or null if an error occured.
	 */
	PktSrc* OpenPktSrc(const std::string& path, bool is_live);

private:

	std::vector<UVIOSourcePtr> sources;
	uv_check_t handle;

	};

}
