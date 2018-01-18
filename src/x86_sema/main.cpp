
/*
 * Simple parser/codegen for x86 semantics
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

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
struct token_string_literal {
  std::string_view value;
};
struct token_digit {
  std::string_view value;
};

using token =
    std::variant<token_at, token_lbrace, token_rbrace, token_lparen,
                 token_rparen, token_lbracket, token_rbracket, token_comma,
                 token_semi, token_colon, token_dot, token_xor, token_xor_eq,
                 token_or, token_or_or, token_or_eq, token_and, token_and_and,
                 token_and_eq, token_percent, token_percent_eq, token_plus,
                 token_plus_eq, token_plus_plus, token_minus, token_minus_eq,
                 token_minus_minus, token_times, token_times_eq, token_div,
                 token_div_eq, token_negate, token_lt, token_lt_eq, token_lt_lt,
                 token_gt, token_gt_eq, token_gt_gt, token_eq, token_eq_eq,
                 token_not, token_not_eq, token_whitespace, token_identifier,
                 token_keyword, token_string_literal, token_digit>;

struct lexer {
  std::string_view input;
  std::uint32_t current;

  struct unexpected_token {};

  lexer(std::string_view in) : input{in}, current{0} {}

  static bool is_digit(char c) {
    return std::isxdigit(c) || c == '.' || c == 'b' || c == 'B' || c == 'x' ||
           c == 'X';
  }

  static bool is_ident_start(char c) { return std::isalpha(c); }

  static bool is_ident(char c) {
    return is_ident_start(c) || std::isdigit(c) || c == '_';
  }

  static bool is_keyword(std::string_view const& v) {
    return std::find(KEYWORDS.begin(), KEYWORDS.end(), v) != KEYWORDS.end();
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

    return {{current - 1, current}, fallback};
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
#define CSPAN {current - 1, current}

    std::pair<char, token> xor_tokens[] = {{'=', {token_xor_eq{}}}};
    std::pair<char, token> or_tokens[] = {{'=', {token_or_eq{}}},
                                          {'|', {token_or_or{}}}};
    std::pair<char, token> and_tokens[] = {{'=', {token_and_eq{}}},
                                           {'&', {token_and_and{}}}};
    std::pair<char, token> mod_tokens[] = {{'=', {token_percent_eq{}}}};
    std::pair<char, token> plus_tokens[] = {{'=', {token_plus_eq{}}},
                                            {'+', {token_plus_plus{}}}};
    std::pair<char, token> minus_tokens[] = {{'=', {token_minus_eq{}}},
                                             {'-', {token_minus_minus{}}}};
    std::pair<char, token> times_tokens[] = {{'=', {token_times_eq{}}}};
    std::pair<char, token> div_tokens[] = {{'=', {token_div_eq{}}}};
    std::pair<char, token> lt_tokens[] = {{'=', {token_lt_eq{}}},
                                          {'<', {token_lt_lt{}}}};
    std::pair<char, token> gt_tokens[] = {{'=', {token_gt_eq{}}},
                                          {'>', {token_gt_gt{}}}};
    std::pair<char, token> eq_tokens[] = {{'=', {token_eq_eq{}}}};
    std::pair<char, token> not_tokens[] = {{'=', {token_not_eq{}}}};

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
        if (c == '"') {
          const auto start = current - 1;
          consume_while([](char c) { return c != '"'; });
          return {{start, current},
                  {token_string_literal{
                      {input.begin() + start + 1, current - start - 2}}}};
        } else if (is_whitespace(c)) {
          const auto start = current - 1;
          consume_while(is_whitespace);
          return {{start, current}, {token_whitespace{}}};
        } else if (is_ident_start(c)) {
          const auto start = current - 1;
          consume_while(is_ident);

          auto view = std::string_view{input.begin() + start, current - start};
          if (is_keyword(view)) {
            return {{start, current}, {token_keyword{view}}};
          }
          return {{start, current}, {token_identifier{view}}};
        } else if (std::isdigit(c)) {
          const auto start = current - 1;
          consume_while(is_digit);

          auto view = std::string_view{input.begin() + start, current - start};
          return {{start, current}, {token_digit{view}}};
        }
        throw unexpected_token{};
    }

#undef CSPAN
  }
};

// AST stuff

using identifier = std::string_view;

struct int_type {
  // If the type is given in the source code this will be set to it, else
  // it will default to either f32 or usize.
  std::string_view type;
  // The string of all the digits belonging to the number.
  // Currently I don't see a reason to parse this into an actual value
  // for the AST.
  std::string_view number;
};

// Asignment operations

struct assign {};      // =
struct assign_add {};  // +=
struct assign_sub {};  // -=
struct assign_div {};  // /=
struct assign_mul {};  // *=
struct assign_and {};  // &=
struct assign_or {};   // |=
struct assign_xor {};  // ^=
struct assign_mod {};  // %=

using assign_op =
    std::variant<assign, assign_add, assign_sub, assign_div, assign_mul,
                 assign_and, assign_or, assign_xor, assign_mod>;

// Binary operators

struct bin_add {};
struct bin_sub {};
struct bin_div {};
struct bin_mul {};
struct bin_b_and {};
struct bin_b_or {};
struct bin_b_xor {};
struct bin_l_and {};
struct bin_l_or {};
struct bin_mod {};
struct bin_shift_left {};
struct bin_shift_right {};
// Comparisons
struct bin_eq {};
struct bin_neq {};
struct bin_lt {};
struct bin_gt {};
struct bin_lteq {};
struct bin_gteq {};

using binary_op = std::variant<bin_add, bin_sub, bin_div, bin_mul, bin_b_and,
                               bin_b_or, bin_b_xor, bin_l_and, bin_l_or,
                               bin_mod, bin_shift_left, bin_shift_right, bin_eq,
                               bin_neq, bin_lt, bin_gt, bin_lteq, bin_gteq>;

// Unary operators
struct un_minus {};     // -a
struct un_plus {};      // +a
struct un_pre_inc {};   // ++a
struct un_pre_dec {};   // --a
struct un_post_inc {};  // a++
struct un_post_dec {};  // a--
struct un_negate {};    // ~a

using unary_op = std::variant<un_minus, un_plus, un_pre_inc, un_pre_dec,
                              un_post_inc, un_post_dec, un_negate>;

// Expressions

struct expr_array_index;
struct expr_bin_op;
struct expr_bool;
struct expr_cast;
struct expr_fun_call;
struct expr_if;
struct expr_int;
struct expr_mem_access;  // member access
struct expr_un_op;
struct expr_var;

using expression = std::variant<expr_array_index, expr_bin_op, expr_bool,
                                expr_cast, expr_fun_call, expr_if, expr_int,
                                expr_mem_access, expr_un_op, expr_var>;

using expression_ptr = std::unique_ptr<expression>;

// Statements

struct stmt_assign;
struct stmt_block;
struct stmt_expression;
struct stmt_fun_def;
struct stmt_il;
struct stmt_import;
struct stmt_insn;  // instruction MOV { /* ...*/ }
struct stmt_let;
struct stmt_pseudo;
struct stmt_return;
struct stmt_root;  // top level block

using statement = std::variant<stmt_assign, stmt_block, stmt_expression,
                               stmt_fun_def, stmt_il, stmt_import, stmt_insn,
                               stmt_let, stmt_pseudo, stmt_return, stmt_root>;

using statement_ptr = std::unique_ptr<statement>;

struct block {
  std::vector<statement> statements;
};

// Expression definitions

struct expr_array_index {
  identifier array;
  expression_ptr index;
};

struct expr_bin_op {
  binary_op type;
  expression_ptr lhs;
  expression_ptr rhs;
};

struct expr_bool {
  bool value;
};

struct expr_cast {
  expression_ptr expr;
  identifier type;
};

struct expr_fun_call {
  identifier name;
  std::vector<expression> arguments;
};

struct expr_if {
  expression_ptr cond;
  block then;
  block else_;
};

struct expr_int {
  int_type value;
};

struct expr_mem_access {
  expression_ptr lhs;
  identifier member;
};

struct expr_un_op {
  unary_op type;
  expression_ptr expr;
};

struct expr_var {
  identifier name;
};

// Statement definitions

struct stmt_assign {
  expression_ptr rhs;
  identifier lhs;
  assign_op op;
};

struct stmt_block {
  block body;
};

struct stmt_expression {
  expression expr;
};

struct stmt_fun_def {
  struct fun_param {
    identifier name;  // TODO: Type ?
  };

  identifier name;
  std::vector<fun_param> arguments;
  block body;
};

struct stmt_il {
  block body;
};

struct stmt_import {
  std::string_view name;
};

struct stmt_insn {
  identifier mnemonic;
  block body;
};

struct stmt_let {
  identifier name;
  expression init;
};

struct stmt_pseudo {
  statement_ptr stmt;
};

struct stmt_return {
  expression expr;
};

struct stmt_root {
  block body;
};

using ast = stmt_root;

int main(int argc, char** argv) { return 0; }
