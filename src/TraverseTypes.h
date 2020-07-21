// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(TraversalCallback, zeek);

namespace zeek {

enum TraversalCode {
	TC_CONTINUE = 0,
	TC_ABORTALL = 1,
	TC_ABORTSTMT = 2,
};

#define HANDLE_TC_STMT_PRE(code) \
	{ \
	if ( (code) == zeek::TC_ABORTALL || (code) == zeek::TC_ABORTSTMT ) \
		return (code); \
	}

#define HANDLE_TC_STMT_POST(code) \
	{ \
	if ( (code) == zeek::TC_ABORTALL ) \
		return (code); \
	else if ( (code) == zeek::TC_ABORTSTMT ) \
		return zeek::TC_CONTINUE; \
	else \
		return (code); \
	}

#define HANDLE_TC_EXPR_PRE(code) \
	{ \
	if ( (code) != zeek::TC_CONTINUE ) \
		return (code); \
	}

#define HANDLE_TC_EXPR_POST(code) \
	return (code);

} // namespace zeek

using TraversalCode [[deprecated("Remove in v4.1. Use zeek::TraversalCode.")]] = zeek::TraversalCode;
constexpr auto TC_CONTINUE [[deprecated("Remove in v4.1. Use zeek::TC_CONTINUE.")]] = zeek::TC_CONTINUE;
constexpr auto TC_ABORTALL [[deprecated("Remove in v4.1. Use zeek::TC_ABORTALL.")]] = zeek::TC_ABORTALL;
constexpr auto TC_ABORTSTMT [[deprecated("Remove in v4.1. Use zeek::TC_ABORTSTMT.")]] = zeek::TC_ABORTSTMT;
