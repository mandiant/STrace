#pragma once

#include <utility>

// https://github.com/mapbox/cpp/blob/master/docs/strong_types.md
namespace util {
    template <typename BaseType, typename TypeName>
    struct strong_type
    {
        explicit constexpr strong_type(BaseType const& value) : value(value) {}
        explicit constexpr strong_type(BaseType&& value) : value(std::move(value)) {}
        operator BaseType& () noexcept { return value; }
        constexpr operator BaseType const& () const noexcept { return value; }
        BaseType value;
    };
}

// create a new type, that acts like base_type, but is a unique type identity. typedef aliases identities, this creates a new identity.
#define strong_typedef(BASE_TYPE, TYPE_NAME) struct TYPE_NAME : util::strong_type<BASE_TYPE, TYPE_NAME>  \
{                                                            \
    using strong_type::strong_type;                        \
}
