#pragma once

#include <stdexcept>
#include <tuple>
#include <utility>

#include <Zydis/DecoderTypes.h>

/* Generic pattern matching part */

namespace pattern_match {
template <typename...>
struct false_ {
  static constexpr bool value = false;
};

namespace detail {
  void no_match() {
    throw std::runtime_error("No case matched the input value");
  }

  template <unsigned, typename, typename, typename>
  struct match_impl;

  template <unsigned I, typename U, typename... Cx, typename... Ax>
  struct match_impl<I, U, std::tuple<Cx...>, std::tuple<Ax...>> {
    static auto call(U&& u, std::tuple<Cx...>& t, Ax&&... ax) {
      auto& c = std::get<I>(t);
      if (c.check(u)) {
        return c.call(std::forward<U>(u), std::forward<Ax>(ax)...);
      }

      if constexpr (sizeof...(Cx) == I + 1) {
        no_match();
      }
      else {
        return match_impl<I + 1,
                          U,
                          std::tuple<Cx...>,
                          std::tuple<Ax...>>
          ::call(std::forward<U>(u), t, std::forward<Ax>(ax)...);
      }
    }
  };
}

template <typename E, typename F>
struct match_case {
  E check;
  F call;
};

//template <typename E, typename F>
//match_case(E, F) -> match_case<E, F>;

// Fuck msvc
template <typename E, typename F>
match_case<E, F> make_match_case(E&& e, F&& f) {
  return match_case<E, F>{
    std::forward<E>(e),
    std::forward<F>(f)
  };
}

template <typename... Cases>
auto match(Cases&&... cases) {
  if constexpr (sizeof...(cases) == 0) {
    static_assert(false_<Cases...>::value, "Can't match on 0 cases");
  }

  return [cases = std::make_tuple(std::forward<Cases>(cases)...)](
    auto&& u, auto&&... args) mutable {
    return detail::match_impl<0,
                              decltype(u),
                              std::tuple<Cases...>,
                              std::tuple<decltype(args)...>>
      ::call(std::forward<decltype(u)>(u), cases,
             std::forward<decltype(args)>(args)...);
  };
}
}

/*void test() {
  using namespace pattern_match;

  auto matcher = match(
    make_match_case(
      [](auto x) {
      return x == 5;
    },
      [](auto x) {
      return x;
    }
    ),
    make_match_case(
      [](auto x) {
      return x == 3;
    },
      [](auto x) {
      return x * 3;
    }
    )
  );

  const auto a = matcher(5);
  assert(a == 5);
  const auto b = matcher(3);
  assert(b == 9);
  matcher(2); // throws
}*/

/* Zydis specific matchers */

/* Rules */
