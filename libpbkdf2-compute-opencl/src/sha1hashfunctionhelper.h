#ifndef LIBPBKDF2_COMPUTE_OPENCL_SHA1HASHFUNCTIONHELPER_H
#define LIBPBKDF2_COMPUTE_OPENCL_SHA1HASHFUNCTIONHELPER_H

#include "uinthashfunctionhelper.h"

namespace libpbkdf2 {
namespace compute {
namespace opencl {

class Sha1HashFunctionHelper : public UIntHashFunctionHelper
{
public:
    Sha1HashFunctionHelper();

    void writeDefinitions(OpenCLWriter &out) const override;

    void writeUpdate(
            OpenCLWriter &writer,
            const std::vector<std::string> &prevState,
            const std::vector<std::string> &inputBlock,
            const std::vector<std::string> &state,
            const std::vector<std::string> &buffer,
            bool swap = false) const override;
};

} // namespace opencl
} // namespace compute
} // namespace libpbkdf2

#endif // LIBPBKDF2_COMPUTE_OPENCL_SHA1HASHFUNCTIONHELPER_H
