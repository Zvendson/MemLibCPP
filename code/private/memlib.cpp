#include "memlib.hpp"

#include "internal.hpp"

namespace memlib
{


	void set_log_callback(const log_callback& cb)
	{
		g_log_func.store(cb, std::memory_order_release);
	}


}
