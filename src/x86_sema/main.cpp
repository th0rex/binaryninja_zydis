
/*
 * Simple parser/codegen for x86 semantics
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <variant>

#include <gsl.hpp>

constexpr static std::array KEYWORDS = {
    "as",   "il",    "fn",   "let",         "return", "import", "if",  "else",
    "true", "false", "void", "instruction", "u8",     "i8",     "u16", "i16",
    "u32",  "i32",   "u64",  "i64",         "f32",    "f64",
};

struct lexer;

struct span {
  std::uint32_t begin;
  std::uint32_t end;

  bool operator==(span const& o) { return begin == o.begin && end == o.end; }
  bool operator!=(span const& o) { return !(*this == o); }
};

struct token_at {};
struct token_lbrace {};
struct token_rbrace {};
struct token_lparen {};
struct token_rparen {};
struct token_lbracket {};
struct token_rbracket {};
struct token_comma {};
struct token_semi {};
struct token_colon {};
struct token_dot {};
struct token_xor {};
struct token_xor_eq {};
struct token_or {};
struct token_or_or {};
struct token_or_eq {};
struct token_and {};
struct token_and_and {};
struct token_and_eq {};
struct token_percent {};
struct token_percent_eq {};
struct token_plus {};
struct token_plus_eq {};
struct token_plus_plus {};
struct token_minus {};
struct token_minus_eq {};
struct token_minus_minus {};
// TODO: use -> for return type ?
struct token_times {};
struct token_times_eq {};
struct token_div {};
struct token_div_eq {};
struct token_negate {};
struct token_lt {};
struct token_lt_eq {};
struct token_lt_lt {};
struct token_gt {};
struct token_gt_eq {};
struct token_gt_gt {};
struct token_eq {};
struct token_eq_eq {};
struct token_not {};
struct token_not_eq {};
struct token_whitespace {};
struct token_identifier {
  std::string_view value;
};
struct token_keyword {
  std::string_view value;
};
// TODO: do we need ? struct token_string_literal
struct token_digit {
  std::string_view value;
};

using token = std::variant<
    token_at, token_lbrace, token_rbrace, token_lparen, token_rparen,
    token_lbracket, token_rbracket, token_comma, token_semi, token_colon,
    token_dot, token_xor, token_xor_eq, token_or, token_or_or, token_or_eq,
    token_and, token_and_and, token_and_eq, token_percent, token_percent_eq,
    token_plus, token_plus_eq, token_plus_plus, token_minus, token_minus_eq,
    token_minus_minus, token_times, token_times_eq, token_div, token_div_eq,
    token_negate, token_lt, token_lt_eq, token_lt_lt, token_gt, token_gt_eq,
    token_gt_gt, token_eq, token_eq_eq, token_not, token_not_eq,
    token_whitespace, token_identifier, token_keyword, token_digit>;

struct lexer {
  std::string_view input;
  std::uint32_t current;

  struct unexpected_token {};

  static bool is_digit(char c) {
    return std::isxdigit(c) || c == '.' || c == 'b' || c == 'B' || c == 'x' ||
           c == 'X';
  }

  static bool is_ident_start(char c) { return std::isalpha(c); }

  static bool is_ident(char c) {
    return is_ident_start(c) || std::isdigit(c) || c == '_';
  }

  static bool is_keyword(std::string_view const& v) {
    return std::find_if(KEYWORDS.begin(), KEYWORDS.end(), [&v](const char* x) {
             return x == v;
           }) != KEYWORDS.end();
  }

  static bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  }

  bool has_more() noexcept { return current < input.size(); }

  char get_current() { return input[current++]; }

  char lookahead() const { return input[current]; }

  std::pair<span, token> lex_multiline_comment() {
    // The '/' was already lexed.
    const auto start = current - 1;
    current++;

    auto seen_star = false;

    while (has_more()) {
      auto c = get_current();

      if (c == '/' && seen_star) {
        break;
      }

      seen_star = c == '*';
    }

    const auto end = current;
    return {{start, end}, {token_whitespace{}}};
  }

  std::pair<span, token> lex_line_comment() {
    const auto start = current - 1;
    current++;

    while (has_more()) {
      if (get_current() == '\n') {
        break;
      }
    }

    const auto end = current;
    return {{start, end}, {token_whitespace{}}};
  }

  std::pair<span, token> maybe_accept_next(
      token fallback, gsl::span<std::pair<char, token>> can_accept) {
    for (auto const & [ c, t ] : can_accept) {
      if (lookahead() == c) {
        current++;
        return {{current - 2, current}, t};
      }
    }

    return {{current - 1, current}, std::move(fallback)};
  }

  template <typename F>
  void consume_while(F&& f) {
    while (has_more()) {
      if (f(lookahead())) {
        current++;
        continue;
      }

      break;
    }
  }

  std::pair<span, token> lex_next() {
  // Span for current character,
#define CSPAN \
  { current - 1, current }

    static std::pair<char, token> xor_tokens[] = {{'=', {token_xor_eq{}}}};
    static std::pair<char, token> or_tokens[] = {{'=', {token_or_eq{}}},
                                                 {'|', {token_or_or{}}}};
    static std::pair<char, token> and_tokens[] = {{'=', {token_and_eq{}}},
                                                  {'&', {token_and_and{}}}};
    static std::pair<char, token> mod_tokens[] = {{'=', {token_percent_eq{}}}};
    static std::pair<char, token> plus_tokens[] = {{'=', {token_plus_eq{}}},
                                                   {'+', {token_plus_plus{}}}};
    static std::pair<char, token> minus_tokens[] = {
        {'=', {token_minus_eq{}}}, {'-', {token_minus_minus{}}}};
    static std::pair<char, token> times_tokens[] = {{'=', {token_times_eq{}}}};
    static std::pair<char, token> div_tokens[] = {{'=', {token_div_eq{}}}};
    static std::pair<char, token> lt_tokens[] = {{'=', {token_lt_eq{}}},
                                                 {'<', {token_lt_lt{}}}};
    static std::pair<char, token> gt_tokens[] = {{'=', {token_gt_eq{}}},
                                                 {'>', {token_gt_gt{}}}};
    static std::pair<char, token> eq_tokens[] = {{'=', {token_eq_eq{}}}};
    static std::pair<char, token> not_tokens[] = {{'=', {token_not_eq{}}}};

    const auto c = get_current();
    switch (c) {
      case '@':
        return {CSPAN, {token_at{}}};
      case '{':
        return {CSPAN, {token_lbrace{}}};
      case '}':
        return {CSPAN, {token_rbrace{}}};
      case '(':
        return {CSPAN, {token_lparen{}}};
      case ')':
        return {CSPAN, {token_rparen{}}};
      case '[':
        return {CSPAN, {token_lbracket{}}};
      case ']':
        return {CSPAN, {token_rbracket{}}};
      case ',':
        return {CSPAN, {token_comma{}}};
      case ';':
        return {CSPAN, {token_semi{}}};
      case ':':
        return {CSPAN, {token_colon{}}};
      case '.':
        return {CSPAN, {token_dot{}}};
      case '~':
        return {CSPAN, {token_negate{}}};
      case '^':
        return maybe_accept_next({token_xor{}}, xor_tokens);
      case '|':
        return maybe_accept_next({token_or{}}, or_tokens);
      case '&':
        return maybe_accept_next({token_and{}}, and_tokens);
      case '%':
        return maybe_accept_next({token_percent{}}, mod_tokens);
      case '+':
        return maybe_accept_next({token_plus{}}, plus_tokens);
      case '-':
        return maybe_accept_next({token_minus{}}, minus_tokens);
      case '*':
        return maybe_accept_next({token_times{}}, times_tokens);
      case '<':
        return maybe_accept_next({token_lt{}}, lt_tokens);
      case '>':
        return maybe_accept_next({token_gt{}}, gt_tokens);
      case '=':
        return maybe_accept_next({token_eq{}}, eq_tokens);
      case '!':
        return maybe_accept_next({token_not{}}, not_tokens);
      case '/':
        if (lookahead() == '*') {
          return lex_multiline_comment();
        } else if (lookahead() == '/') {
          return lex_line_comment();
        } else {
          return maybe_accept_next({token_div{}}, div_tokens);
        }

      default:
        if (is_whitespace(c)) {
          const auto start = current - 1;
          consume_while(is_whitespace);
          return {{start, current}, {token_whitespace{}}};
        } else if (is_ident_start(c)) {
          const auto start = current - 1;
          consume_while(is_ident);

          auto view = std::string_view{input.begin() + start, current};
          if (is_keyword(view)) {
            return {{start, current}, {token_keyword{std::move(view)}}};
          }
          return {{start, current}, {token_identifier{std::move(view)}}};
        } else if (std::isdigit(c)) {
          const auto start = current - 1;
          consume_while(is_digit);

          auto view = std::string_view{input.begin() + start, current};
          return {{start, current}, {token_digit{std::move(view)}}};
        }
        throw unexpected_token{};
    }

#undef CSPAN
  }
};

int main(int argc, char** argv) { return 0; }
