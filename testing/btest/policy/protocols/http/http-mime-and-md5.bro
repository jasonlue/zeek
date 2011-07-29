# This tests md5 calculation for a specified mime type.  The http.log
# will normalize mime types other than the target type to prevent sensitivity
# to varying versions of libmagic.

# @TEST-REQUIRES: grep -q '#define HAVE_LIBMAGIC' $BUILD/config.h
# @TEST-EXEC: bro -r $TRACES/http-pipelined-requests.trace %INPUT > output
# @TEST-EXEC: btest-diff http.log

@load protocols/http

redef HTTP::generate_md5 += /image\/png/;

event bro_init()
	{
	Log::remove_default_filter(HTTP::HTTP);
	Log::add_filter(HTTP::HTTP, [$name="normalized-mime-types",
	                             $pred=function(rec: HTTP::Info): bool
		{
		if ( rec?$mime_type && HTTP::generate_md5 != rec$mime_type )
				rec$mime_type = "FAKE_MIME";
		return T;
		}
	]);
	}
