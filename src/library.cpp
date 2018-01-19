#include <array>
#include <cinttypes>

#include "Zydis/Zydis.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

#define CHECK_RESULT(r)                \
  do {                                 \
    if ((r) != ZYDIS_STATUS_SUCCESS) { \
      return false;                    \
    }                                  \
  } while (0);

#define CHECK_RESULT2(r)                           \
  do {                                             \
    if (auto a = (r); a != ZYDIS_STATUS_SUCCESS) { \
      return a;                                    \
    }                                              \
  } while (0);

template <size_t address_size>
struct address_traits;

template <>
struct address_traits<4> {
  constexpr static const char* arch_name = "Zydis x86";
  constexpr static const char* bn_arch_name = "x86";
  constexpr static ZydisAddressWidth address_width = ZYDIS_ADDRESS_WIDTH_32;
  constexpr static ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
};

template <>
struct address_traits<8> {
  constexpr static const char* arch_name = "Zydis x64";
  constexpr static const char* bn_arch_name = "x86_64";
  constexpr static ZydisAddressWidth address_width = ZYDIS_ADDRESS_WIDTH_64;
  constexpr static ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
};

static bool is_branch(const ZydisDecodedInstruction& insn) {
  const auto c = insn.meta.category;
  return c == ZYDIS_CATEGORY_COND_BR || c == ZYDIS_CATEGORY_CALL ||
         c == ZYDIS_CATEGORY_RET || c == ZYDIS_CATEGORY_SYSCALL ||
         c == ZYDIS_CATEGORY_UNCOND_BR;
}

static void add_branch(BNBranchType type, BNBranchType fall_back,
                       const ZydisDecodedInstruction& insn,
                       InstructionInfo& result) {
  const auto& op = insn.operands[0];

  if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    uint64_t value = 0;
    ZydisCalcAbsoluteAddress(&insn, &op, &value);
    result.AddBranch(type, value);
  } else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
    result.AddBranch(fall_back);
  } else {
    assert(0);
  }
}

static void add_cond_branch(const ZydisDecodedInstruction& insn,
                            InstructionInfo& result) {
  switch (insn.mnemonic) {
      // jb, jbe, jcxz, jecxz, jkzd, jl, jle, jo, jp, jrcxz, js, jz, loop, loope
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:

      // jknzd, jnb, jnbe, jnl, jnle, jno, jnp, jns, jnz, loopne
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_LOOPNE:
      add_branch(BNBranchType::TrueBranch, BNBranchType::IndirectBranch, insn,
                 result);
      result.AddBranch(BNBranchType::FalseBranch,
                       insn.instrAddress + insn.length);
      break;
    default:
      assert(0);
  }
}

static void add_branches(const ZydisDecodedInstruction& insn,
                         InstructionInfo& result) {
  const auto c = insn.meta.category;
  if (c == ZYDIS_CATEGORY_CALL) {
    assert(insn.operandCount > 0);

    add_branch(BNBranchType::CallDestination, BNBranchType::CallDestination,
               insn, result);
  } else if (c == ZYDIS_CATEGORY_COND_BR) {
    assert(insn.operandCount > 0);

    add_cond_branch(insn, result);
  } else if (c == ZYDIS_CATEGORY_RET) {
    result.AddBranch(BNBranchType::FunctionReturn);
  } else if (c == ZYDIS_CATEGORY_SYSCALL) {
    result.AddBranch(BNBranchType::SystemCall);
  } else if (c == ZYDIS_CATEGORY_UNCOND_BR) {
    assert(insn.operandCount > 0);

    add_branch(BNBranchType::UnconditionalBranch, BNBranchType::IndirectBranch,
               insn, result);
  } else {
    assert(false &&
           "add_branches shouldn't be called with an instruction that isn't a "
           "branch");
  }
}

template <size_t address_size>
class zydis_architecture : public Architecture {
  using address_traits = address_traits<address_size>;

  ZydisDecoder _decoder;
  ZydisFormatter _formatter;

  ZydisFormatterFormatFunc _orig_print_prefixes = nullptr;
  ZydisFormatterFormatFunc _orig_print_mnemonic = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_reg = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_mem = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_ptr = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_imm = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_operand_size = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_segment = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_displacement = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_immediate = nullptr;
  ZydisFormatterFormatAddressFunc _orig_print_address = nullptr;
  ZydisFormatterFormatDecoratorFunc _orig_print_decorator = nullptr;
  ZydisFormatterPrintOperandSeperatorFunc _orig_print_operand_seperator =
      nullptr;

  std::array<char, 512> _buffer;

  Architecture* _arch;

  struct hook_data {
    hook_data(zydis_architecture<address_size>& arch,
              std::vector<InstructionTextToken>& instruction_text_tokens)
        : arch(arch), tokens(instruction_text_tokens) {}

    zydis_architecture<address_size>& arch;
    std::vector<InstructionTextToken>& tokens;
  };

#define TRANSLATE_STRING(n, ...)                    \
  auto* data = static_cast<hook_data*>(user_data);  \
  auto* before = *buffer;                           \
  CHECK_RESULT2(data->arch._orig_##n(__VA_ARGS__)); \
  auto* end = *buffer;                              \
  std::string str{before, end};

#define TRANSLATE_VALUE(n, t, v, ...)                        \
  TRANSLATE_STRING(n, __VA_ARGS__);                          \
  data->tokens.push_back(InstructionTextToken{(t), str, v}); \
  return ZYDIS_STATUS_SUCCESS;

#define TRANSLATE(n, t, ...) TRANSLATE_VALUE(n, t, 0, __VA_ARGS__)

  static ZydisStatus print_prefixes(const ZydisFormatter* f, char** buffer,
                                    ZydisUSize buffer_len,
                                    const ZydisDecodedInstruction* insn,
                                    void* user_data) {
    TRANSLATE(print_prefixes, TextToken, f, buffer, buffer_len, insn,
              user_data);
  }

  static ZydisStatus print_mnemonic(const ZydisFormatter* f, char** buffer,
                                    ZydisUSize buffer_len,
                                    const ZydisDecodedInstruction* insn,
                                    void* user_data) {
    TRANSLATE(print_mnemonic, InstructionToken, f, buffer, buffer_len, insn,
              user_data);
  }

  static ZydisStatus format_operand_reg(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    TRANSLATE(format_operand_reg, RegisterToken, f, buffer, buffer_len, insn,
              operand, user_data);
  }

  static ZydisStatus format_operand_mem(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    auto* data = static_cast<hook_data*>(user_data);

    data->tokens.push_back(InstructionTextToken{BeginMemoryOperandToken, "["});

    // Adapted from zydis code
    const char* buf_end = *buffer + buffer_len;
    if (operand->mem.disp.hasDisplacement &&
        ((operand->mem.base == ZYDIS_REGISTER_NONE) ||
         (operand->mem.base == ZYDIS_REGISTER_EIP) ||
         (operand->mem.base == ZYDIS_REGISTER_RIP)) &&
        (operand->mem.index == ZYDIS_REGISTER_NONE) &&
        (operand->mem.scale == 0)) {
      CHECK_RESULT2(data->arch._orig_format_operand_mem(
          f, buffer, buffer_len, insn, operand, user_data));
    } else {
      if (operand->mem.base != ZYDIS_REGISTER_NONE) {
        const char* reg = ZydisRegisterGetString(operand->mem.base);
        if (reg == nullptr) {
          return ZYDIS_STATUS_INVALID_PARAMETER;
        }

        data->tokens.push_back(InstructionTextToken{RegisterToken, reg});
      }
      if ((operand->mem.index != ZYDIS_REGISTER_NONE) &&
          (operand->mem.type != ZYDIS_MEMOP_TYPE_MIB)) {
        const char* reg = ZydisRegisterGetString(operand->mem.index);
        if (reg == nullptr) {
          return ZYDIS_STATUS_INVALID_PARAMETER;
        }
        if (operand->mem.base != ZYDIS_REGISTER_NONE) {
          data->tokens.push_back(InstructionTextToken{TextToken, " + "});
        }
        data->tokens.push_back(InstructionTextToken{RegisterToken, reg});
        if (operand->mem.scale != 0) {
          char b[32] = {'\0'};
          snprintf(b, 32, "%d", operand->mem.scale);
          data->tokens.push_back(InstructionTextToken{TextToken, " * "});
          data->tokens.push_back(
              InstructionTextToken{IntegerToken, b, operand->mem.scale});
        }
      }
      CHECK_RESULT2(print_displacement(f, buffer, buf_end - *buffer, insn,
                                       operand, user_data));
    }

    data->tokens.push_back(InstructionTextToken{EndMemoryOperandToken, "]"});

    return ZYDIS_STATUS_SUCCESS;
  }

  static ZydisStatus format_operand_ptr(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    TRANSLATE(format_operand_ptr, TextToken, f, buffer, buffer_len, insn,
              operand, user_data);
  }

  static ZydisStatus format_operand_imm(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    auto* data = static_cast<hook_data*>(user_data);
    CHECK_RESULT2(data->arch._orig_format_operand_imm(
        f, buffer, buffer_len, insn, operand, user_data));

    return ZYDIS_STATUS_SUCCESS;
  }

  static ZydisStatus print_operand_size(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    TRANSLATE(print_operand_size, TextToken, f, buffer, buffer_len, insn,
              operand, user_data);
  }

  static ZydisStatus print_segment(const ZydisFormatter* f, char** buffer,
                                   ZydisUSize buffer_len,
                                   const ZydisDecodedInstruction* insn,
                                   const ZydisDecodedOperand* operand,
                                   void* user_data) {
    TRANSLATE(print_segment, TextToken, f, buffer, buffer_len, insn, operand,
              user_data);
  }

  static ZydisStatus print_displacement(const ZydisFormatter* f, char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        const ZydisDecodedOperand* operand,
                                        void* user_data) {
    auto* data = static_cast<hook_data*>(user_data);
    auto* before = *buffer;
    CHECK_RESULT2(data->arch._orig_print_displacement(
        f, buffer, buffer_len, insn, operand, user_data));
    auto* after = *buffer;

    auto start = 0;
    if (before[0] == '+') {
      data->tokens.push_back(InstructionTextToken{TextToken, " + "});
      ++start;
    }
    data->tokens.push_back(
        InstructionTextToken{IntegerToken, std::string{before + start, after}});

    return ZYDIS_STATUS_SUCCESS;
  }

  static ZydisStatus print_immediate(const ZydisFormatter* f, char** buffer,
                                     ZydisUSize buffer_len,
                                     const ZydisDecodedInstruction* insn,
                                     const ZydisDecodedOperand* operand,
                                     void* user_data) {
    TRANSLATE_VALUE(print_immediate, IntegerToken, operand->imm.value.u, f,
                    buffer, buffer_len, insn, operand, user_data);
  }

  static ZydisStatus print_address(const ZydisFormatter* f, char** buffer,
                                   ZydisUSize buffer_len,
                                   const ZydisDecodedInstruction* insn,
                                   const ZydisDecodedOperand* operand,
                                   ZydisU64 address, void* user_data) {
    TRANSLATE_VALUE(print_address, PossibleAddressToken, address, f, buffer,
                    buffer_len, insn, operand, address, user_data);
  }

  static ZydisStatus print_decorator(const ZydisFormatter* f, char** buffer,
                                     ZydisUSize buffer_len,
                                     const ZydisDecodedInstruction* insn,
                                     const ZydisDecodedOperand* operand,
                                     ZydisDecoratorType type, void* user_data) {
    TRANSLATE_STRING(print_decorator, f, buffer, buffer_len, insn, operand,
                     type, user_data);

    size_t pos = 0;
    for (pos = str.find(" {", pos); pos != std::string::npos;
         pos = str.find(" {", pos)) {
      data->tokens.push_back(InstructionTextToken{TextToken, " {"});

      const auto end_pos = str.find('}', pos);
      assert(end_pos != std::string::npos);
      assert(pos + 2 != end_pos);

      data->tokens.push_back(InstructionTextToken{
          RegisterToken,
          std::string{str.begin() + pos + 2, str.begin() + end_pos}});
      data->tokens.push_back(InstructionTextToken{TextToken, "}"});

      pos = end_pos;
    }

    return ZYDIS_STATUS_SUCCESS;
  }

  static ZydisStatus print_operand_seperator(const ZydisFormatter* f,
                                             char** buffer,
                                             ZydisUSize buffer_len,
                                             ZydisU8 index, void* user_data) {
    auto* d2 = static_cast<hook_data*>(user_data);

    if (d2->tokens.size() >= 2 &&
        d2->tokens[d2->tokens.size() - 2].type == OperandSeparatorToken &&
        d2->tokens[d2->tokens.size() - 2].text == ", ") {
      return ZYDIS_STATUS_SUCCESS;
    }

    TRANSLATE(print_operand_seperator, OperandSeparatorToken, f, buffer,
              buffer_len, index, user_data);
  }

#undef TRANSLATE
#undef TRANSLATE_VALUE
#undef TRANSLATE_STRING

  bool set_formatter_hooks() {
    const void* c = nullptr;

#define SET_HOOK(h, f)                                     \
  c = (const void*)(&(f));                                 \
  CHECK_RESULT(ZydisFormatterSetHook(&_formatter, h, &c)); \
  _orig_##f = (decltype(_orig_##f))(c);

    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_PREFIXES, print_prefixes);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_MNEMONIC, print_mnemonic);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_REG, format_operand_reg);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_MEM, format_operand_mem);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_PTR, format_operand_ptr);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_IMM, format_operand_imm);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_OPERANDSIZE, print_operand_size);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_SEGMENT, print_segment);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_DISPLACEMENT, print_displacement);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_IMMEDIATE, print_immediate);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_ADDRESS, print_address);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_DECORATOR, print_decorator);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_OPERAND_SEPERATOR,
             print_operand_seperator);

#undef SET_HOOK

    return true;
  }

 public:
  zydis_architecture()
      : Architecture(address_traits::arch_name),
        _arch{new CoreArchitecture(
            BNGetArchitectureByName(address_traits::bn_arch_name))},
        _decoder{},
        _formatter{},
        _buffer{} {
    if (ZydisDecoderInit(&_decoder, address_traits::machine_mode,
                         address_traits::address_width) !=
        ZYDIS_STATUS_SUCCESS) {
      throw std::runtime_error("Could not initialize the zydis decoder");
    }

    if (ZydisFormatterInit(&_formatter, ZYDIS_FORMATTER_STYLE_INTEL) !=
        ZYDIS_STATUS_SUCCESS) {
      throw std::runtime_error("Could not initialize the zydis formatter");
    }

    if (!set_formatter_hooks()) {
      throw std::runtime_error("Could not set formatter hooks");
    }

    if (ZydisFormatterSetProperty(&_formatter,
                                  ZYDIS_FORMATTER_PROP_HEX_UPPERCASE,
                                  0) != ZYDIS_STATUS_SUCCESS) {
      throw std::runtime_error("Could not set formatter property");
    }

    if (ZydisFormatterSetProperty(&_formatter,
                                  ZYDIS_FORMATTER_PROP_FORCE_OPERANDSIZE,
                                  1) != ZYDIS_STATUS_SUCCESS) {
      throw std::runtime_error("Could not force operand size");
    }
  }

  size_t GetAddressSize() const override { return address_size; }

  size_t GetDefaultIntegerSize() const override { return GetAddressSize(); }

  bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t max_len,
                          InstructionInfo& result) override {
    ZydisDecodedInstruction insn{};
    CHECK_RESULT(
        ZydisDecoderDecodeBuffer(&_decoder, data, max_len, addr, &insn));

    result.length = insn.length;

    if (is_branch(insn)) {
      add_branches(insn, result);
    }

    return true;
  }

  bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
                          std::vector<InstructionTextToken>& result) override {
    ZydisDecodedInstruction insn{};
    hook_data hd{*this, result};

    CHECK_RESULT(ZydisDecoderDecodeBuffer(&_decoder, data, len, addr, &insn));
    CHECK_RESULT(ZydisFormatterFormatInstructionEx(
        &_formatter, &insn, _buffer.data(), _buffer.size(), &hd));

    len = insn.length;

    return true;
  }

  BNEndianness GetEndianness() const override { return LittleEndian; }

  bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
                                LowLevelILFunction& il) override {
    return _arch->GetInstructionLowLevelIL(data, addr, len, il);
  }

  size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size,
                                uint32_t flag_write_type, uint32_t flag,
                                BNRegisterOrConstant* operands,
                                size_t operand_count,
                                LowLevelILFunction& il) override {
    return _arch->GetFlagWriteLowLevelIL(op, size, flag_write_type, flag,
                                         operands, operand_count, il);
  }

  std::string GetRegisterName(uint32_t reg) override {
    return _arch->GetRegisterName(reg);
  }

  std::string GetFlagName(uint32_t flag) override {
    return _arch->GetFlagName(flag);
  }

  std::vector<uint32_t> GetAllFlags() override { return _arch->GetAllFlags(); }

  std::string GetFlagWriteTypeName(uint32_t flags) override {
    return _arch->GetFlagWriteTypeName(flags);
  }

  std::vector<uint32_t> GetAllFlagWriteTypes() override {
    return _arch->GetAllFlagWriteTypes();
  }

  BNFlagRole GetFlagRole(uint32_t flag) override {
    return _arch->GetFlagRole(flag);
  }

  std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
      BNLowLevelILFlagCondition cond) override {
    return _arch->GetFlagsRequiredForFlagCondition(cond);
  }

  std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(
      uint32_t write_type) override {
    return _arch->GetFlagsWrittenByFlagWriteType(write_type);
  }

  bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr,
                                   size_t len) override {
    return _arch->IsNeverBranchPatchAvailable(data, addr, len);
  }

  bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr,
                                    size_t len) override {
    return _arch->IsAlwaysBranchPatchAvailable(data, addr, len);
  }

  bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr,
                                    size_t len) override {
    return _arch->IsInvertBranchPatchAvailable(data, addr, len);
  }

  bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr,
                                         size_t len) override {
    return _arch->IsSkipAndReturnZeroPatchAvailable(data, addr, len);
  }

  bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr,
                                          size_t len) override {
    return _arch->IsSkipAndReturnValuePatchAvailable(data, addr, len);
  }

  bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override {
    return _arch->ConvertToNop(data, addr, len);
  }

  bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override {
    return _arch->AlwaysBranch(data, addr, len);
  }

  bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override {
    return _arch->InvertBranch(data, addr, len);
  }

  bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len,
                          uint64_t value) override {
    return _arch->SkipAndReturnValue(data, addr, len, value);
  }

  std::vector<uint32_t> GetFullWidthRegisters() override {
    return _arch->GetFullWidthRegisters();
  }

  std::vector<uint32_t> GetGlobalRegisters() override {
    return _arch->GetGlobalRegisters();
  }

  std::vector<uint32_t> GetAllRegisters() override {
    return _arch->GetAllRegisters();
  }

  BNRegisterInfo GetRegisterInfo(uint32_t reg) override {
    return _arch->GetRegisterInfo(reg);
  }

  uint32_t GetStackPointerRegister() override {
    return _arch->GetStackPointerRegister();
  }

  bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result,
                std::string& errors) override {
    return _arch->Assemble(code, addr, result, errors);
  }
};

extern "C" {
BINARYNINJAPLUGIN void CorePluginDependencies() {
  SetCurrentPluginLoadOrder(LatePluginLoadOrder);
}

BINARYNINJAPLUGIN bool CorePluginInit() {
  auto* zydis_arch = new zydis_architecture<4>();
  Architecture::Register(zydis_arch);

  auto* zydis_x64_arch = new zydis_architecture<8>();
  Architecture::Register(zydis_x64_arch);

  BinaryViewType::RegisterArchitecture("ELF", 3, LittleEndian, zydis_arch);
  BinaryViewType::RegisterArchitecture("PE", 0x14c, LittleEndian, zydis_arch);
  BinaryViewType::RegisterArchitecture("Mach-O", 0x7, LittleEndian, zydis_arch);

  BinaryViewType::RegisterArchitecture("ELF", 0x3E, LittleEndian,
                                       zydis_x64_arch);
  BinaryViewType::RegisterArchitecture("PE", 0x8664, LittleEndian,
                                       zydis_x64_arch);

  // PE: 0x8664
  // ELF: 0x3E
  // no idea about Mach-o

  return true;
}
};
