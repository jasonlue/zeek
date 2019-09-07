#include "Manager.h"

#include "Component.h"
#include "plugin/Manager.h"

#define DEFAULT_PREFIX "uvpcap"

using namespace uvsource;

static void check_handle(uv_check_t* handle)
	{
	Manager::Get().FlushClosed();
	}

Manager& Manager::Get()
	{
	static Manager manager;
	return manager;
	}

void Manager::Init(uv_loop_t* loop)
	{
	uv_check_init(loop, &handle);
	uv_check_start(&handle, check_handle);
	}

void Manager::Shutdown()
	{
	uv_check_stop(&handle);

	// TODO: close and flush everything?
	}

void Manager::FlushClosed()
	{
	for ( auto it = sources.begin(); it != sources.end(); )
		{
		if ( ! (*it)->IsOpen() )
			it = sources.erase(it);
		else
			++it;
		}

	// If we're out of sources, shut down this manager so that the loop will end
	// if the only thing holding it open was the manager.
	if ( sources.empty() )
		uv_check_stop(&handle);
	}

void Manager::Register(iosource::IOSource* source)
	{
	source->Init();
	sources.push_back(source);
	}

static std::pair<std::string, std::string> split_prefix(std::string path)
	{
	// See if the path comes with a prefix telling us which type of
	// PktSrc to use. If not, choose default.
	std::string prefix;

	std::string::size_type i = path.find("::");
	if ( i != std::string::npos )
		{
		prefix = path.substr(0, i);
		path = path.substr(i + 2, std::string::npos);
		}
	else
		prefix = DEFAULT_PREFIX;

	return std::make_pair(prefix, path);
	}

PktSrc* Manager::OpenPktSrc(const std::string& path, bool is_live)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet sources of the requested prefix.
	PktSrcComponent* component = nullptr;

	std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();

	for ( auto c : all_components )
		{
		if ( c->HandlesPrefix(prefix) &&
		     ((  is_live && c->DoesLive() ) ||
		      (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}

	if ( ! component )
		{
		reporter->Error("UVIO Manager: type of packet source '%s' not recognized, or mode not supported", prefix.c_str());
		return nullptr;
		}

	// Instantiate packet source. Instead of taking a loop as an argument to this method, we pass the loop from
	// the manager's uv_check handle, so that the packet source ends up in the same loop.
	PktSrc* ps = (*component->Factory())(handle.loop, npath, is_live);
	assert(ps);

	if ( ! ps->IsOpen() && ps->IsError() )
		// Set an error message if it didn't open successfully.
		ps->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created UV packet source of type %s for %s", component->Name().c_str(), npath.c_str());

	Register(ps);
	return ps;
	}
