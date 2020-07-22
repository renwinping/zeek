// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include "util.h" // for ptr_compat_int

namespace zeek::detail {

using int_list = std::vector<ptr_compat_int>;

class CCL {
public:
	CCL();
	~CCL();

	void Add(int sym);
	void Negate();
	bool IsNegated()		{ return negated != 0; }
	int Index()		{ return index; }

	void Sort();

	int_list* Syms()	{ return syms; }

	void ReplaceSyms(int_list* new_syms)
				{ delete syms; syms = new_syms; }

	unsigned int MemoryAllocation() const;

protected:
	int_list* syms;
	int negated;
	int index;
};

} // namespace zeek::detail

using int_list [[deprecated("Remove in v4.1. Use zeek::detail::int_list.")]] = zeek::detail::int_list;
using CCL [[deprecated("Remove in v4.1. Use zeek::detail::CCL.")]] = zeek::detail::CCL;
