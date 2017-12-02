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
void no_match() { throw std::runtime_error("No case matched the input value"); }

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
      return decltype(
          match_impl<I, U, std::tuple<Cx...>, std::tuple<Ax...>>::call(
              std::forward<U>(u), t, std::forward<Ax>(ax)...)){};
    } else {
      return match_impl<I + 1, U, std::tuple<Cx...>, std::tuple<Ax...>>::call(
          std::forward<U>(u), t, std::forward<Ax>(ax)...);
    }
  }
};
}  // namespace detail

template <typename E, typename F>
struct match_case {
  E check;
  F call;
};

template <typename E, typename F>
match_case<E, F> make_match_case(E&& e, F&& f) {
  return match_case<E, F>{std::forward<E>(e), std::forward<F>(f)};
}

template <typename E>
struct expression {
  template <typename F>
  auto operator=(F&& func) {
    return make_match_case(static_cast<E&>(*this).get_lambda(),
                           std::forward<F>(func));
  }
};

template <typename T>
struct is_mapper {
  static constexpr bool value = false;
};

template <typename T>
inline constexpr bool is_mapper_v = is_mapper<T>::value;

template <typename T>
inline constexpr bool is_expression_v = std::is_base_of_v<expression<T>, T>;

struct _identity : expression<_identity> {
  auto get_lambda() {
    return [](auto i) { return i; };
  }

  using expression<_identity>::operator=;
};

template <>
struct is_mapper<_identity> {
  static constexpr bool value = true;
};

auto identity() { return _identity{}; }

template <typename F>
struct _function : expression<_function<F>> {
  F _f;

  _function(F&& f) : _f{std::forward<F>(f)} {}

  auto get_lambda() {
    return [f = _f](auto i) { return f(i); };
  }

  using expression<_function<F>>::operator=;
};

template <typename F>
struct is_mapper<_function<F>> {
  static constexpr bool value = true;
};

template <typename F>
auto function(F&& f) {
  return _function<F>{std::forward<F>(f)};
}

// TODO: Operator >> for chaining functions

template <typename T, typename U>
struct _eq : expression<_eq<T, U>> {
  T _t;
  U _u;

  _eq(T&& t, U&& u) : _t{std::forward<T>(t)}, _u{std::forward<U>(u)} {}

  _eq(const _eq&) = delete;
  _eq(_eq&&) = default;
  _eq& operator=(const _eq&) = delete;
  _eq& operator=(_eq&&) = default;

  auto get_lambda() {
    return [ t = std::move(_t), u = std::move(_u) ](auto i) {
      return t(i) == u;
    };
  }

  using expression<_eq<T, U>>::operator=;
};

template <typename A, typename B, typename>
auto operator==(A&& a, B&& b);

template <typename A, typename B,
          typename = std::enable_if_t<is_mapper_v<std::remove_reference_t<A>>>>
auto operator==(A&& a, B&& b) {
  return _eq<A, B>{std::forward<A>(a), std::forward<B>(b)};
}

template <typename T, typename U>
struct _or : expression<_or<T, U>> {
  T _t;
  U _u;

  _or(T&& t, U&& u) : _t{std::forward<T>(t)}, _u{std::forward<U>(u)} {}

  _or(const _or&) = delete;
  _or(_or&&) = default;
  _or& operator=(const _or&) = delete;
  _or& operator=(_or&&) = default;

  auto get_lambda() {
    return [ t = std::move(_t), u = std::move(_u) ](auto i) {
      return t(i) || u(i);
    };
  }

  using expression<_or<T, U>>::operator=;
};

template <typename A, typename B, typename>
auto operator||(A&& a, B&& b);

template <typename A, typename B,
          typename = std::enable_if_t<is_expression_v<A> && is_expression_v<B>>>
auto operator||(A&& a, B&& b) {
  return _or<A, B>{std::forward<A>(a), std::forward<B>(b)};
}

template <typename T, typename U>
struct _and : expression<_and<T, U>> {
  T _t;
  U _u;

  _and(T&& t, U&& u) : _t{std::forward<T>(t)}, _u{std::forward<U>(u)} {}

  _and(const _and&) = delete;
  _and(_and&&) = default;
  _and& operator=(const _and&) = delete;
  _and& operator=(_and&&) = default;

  auto get_lambda() {
    return [ t = std::move(_t), u = std::move(_u) ](auto i) {
      return t(i) && u(i);
    };
  }

  using expression<_and<T, U>>::operator=;
};

template <typename A, typename B, typename>
auto operator&&(A&& a, B&& b);

template <typename A, typename B,
          typename = std::enable_if_t<is_expression_v<A> && is_expression_v<B>>>
auto operator&&(A&& a, B&& b) {
  return _and<A, B>{std::forward<A>(a), std::forward<B>(b)};
}

template <typename... Cases>
auto match(Cases&&... cases) {
  if constexpr (sizeof...(cases) == 0) {
    static_assert(false_<Cases...>::value, "Can't match on 0 cases");
  }

  return [cases = std::make_tuple(std::forward<Cases>(cases)...)](
      auto&& u, auto&&... args) mutable {
    return detail::match_impl<
        0, decltype(u), std::tuple<Cases...>,
        std::tuple<decltype(args)...>>::call(std::forward<decltype(u)>(u),
                                             cases,
                                             std::forward<decltype(args)>(
                                                 args)...);
  };
}
}  // namespace pattern_match

void test() {
  using namespace pattern_match;

  auto i = identity();

  auto m2 = match(i == 5 = [](auto x) { return x; },
                  i == 3 || i == 4 || i == 9 = [](auto x) { return x * 1337; });

  auto matcher = match(
      make_match_case([](auto x) { return x == 5; }, [](auto x) { return x; }),
      make_match_case([](auto x) { return x == 3; },
                      [](auto x) { return x * 3; }));

  const auto a = matcher(5);
  assert(a == 5);
  const auto b = matcher(3);
  assert(b == 9);
  matcher(2);  // throws
}

/* Zydis specific matchers */

namespace zydis_matchers {
using pattern_match::function;

inline auto mnemonic =
    function([](const ZydisDecodedInstruction& insn) { return insn.mnemonic; });
}  // namespace zydis_matchers

void zydis_test() {
  using namespace pattern_match;
  using namespace zydis_matchers;

  auto m = match(mnemonic == ZYDIS_MNEMONIC_MOV =
                     [](const ZydisDecodedInstruction& insn) { return insn; });
}

/* Rules */
