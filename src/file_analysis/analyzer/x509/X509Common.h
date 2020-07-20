// See the file "COPYING" in the main distribution directory for copyright.

// Common base class for the X509 and OCSP analyzer, which share a fair amount of
// code

#pragma once

#include "file_analysis/Analyzer.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandlerPtr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Reporter, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);

namespace zeek {
template <class T> class IntrusivePtr;
using StringValPtr = zeek::IntrusivePtr<StringVal>;
}

namespace file_analysis {

class Tag;
class File;

class X509Common : public file_analysis::Analyzer {
public:
	~X509Common() override {};

	/**
	 * Retrieve an X509 extension value from an OpenSSL BIO to which it was
	 * written.
	 *
	 * @param bio the OpenSSL BIO to read. It will be freed by the function,
	 * including when an error occurs.
	 *
	 * @param f an associated file, if any (used for error reporting).
	 *
	 * @return The X509 extension value.
	 */
	static zeek::StringValPtr GetExtensionFromBIO(BIO* bio, File* f = nullptr);

	static double GetTimeFromAsn1(const ASN1_TIME* atime, File* f, zeek::Reporter* reporter);

protected:
	X509Common(const file_analysis::Tag& arg_tag,
	           zeek::RecordValPtr arg_args, File* arg_file);

	void ParseExtension(X509_EXTENSION* ex, const zeek::EventHandlerPtr& h, bool global);
	void ParseSignedCertificateTimestamps(X509_EXTENSION* ext);
	virtual void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) = 0;
};

}
