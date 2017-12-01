#define _CRT_SECURE_NO_WARNINGS

#include "binaryninjaapi.h"
#include "Zydis/Zydis.h"
#include <inttypes.h>

using namespace BinaryNinja;

#define CHECK_RESULT(r) \
  do { \
    if((r) != ZYDIS_STATUS_SUCCESS) { \
      return false; \
    } \
  } while(0);

template <size_t address_size>
struct address_traits;

template <>
struct address_traits<4> {
  constexpr static const char* arch_name = "Zydis x86";
  constexpr static ZydisAddressWidth address_width = ZYDIS_ADDRESS_WIDTH_32;
  constexpr static ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
};

template <>
struct address_traits<8> {
  constexpr static const char* arch_name = "Zydis x64";
  constexpr static ZydisAddressWidth address_width = ZYDIS_ADDRESS_WIDTH_64;
  constexpr static ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
};

static bool is_branch(const ZydisDecodedInstruction& insn) {
  const auto c = insn.meta.category;
  return c == ZYDIS_CATEGORY_COND_BR || c == ZYDIS_CATEGORY_CALL || c ==
    ZYDIS_CATEGORY_RET || c == ZYDIS_CATEGORY_SYSCALL || c ==
    ZYDIS_CATEGORY_UNCOND_BR;
}

static void add_branches(const ZydisDecodedInstruction& insn,
                         InstructionInfo& result) {
  const auto c = insn.meta.category;
  if (c == ZYDIS_CATEGORY_CALL) {
    assert(insn.operandCount > 0);

    // TODO for all things that use operands
    if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      result.AddBranch(BNBranchType::CallDestination,
                       insn.operands[0].imm.value.u);
    }
    else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
      result.AddBranch(BNBranchType::UnresolvedBranch);
    }
  }
  else if (c == ZYDIS_CATEGORY_COND_BR) {
    assert(insn.operandCount > 0);
    result.AddBranch(BNBranchType::IndirectBranch,
                     insn.operands[0].imm.value.u);
  }
  else if (c == ZYDIS_CATEGORY_RET) {
    result.AddBranch(BNBranchType::FunctionReturn);
  }
  else if (c == ZYDIS_CATEGORY_SYSCALL) {
    result.AddBranch(BNBranchType::SystemCall);
  }
  else if (c == ZYDIS_CATEGORY_UNCOND_BR) {
    assert(insn.operandCount > 0);

    uint64_t value = 0;
    ZydisCalcAbsoluteAddress(&insn, &insn.operands[0], &value);

    result.AddBranch(BNBranchType::TrueBranch,
                     value);

    Log(InfoLog,
        "immediate value: %" PRIu64 "  (relative: %d, absolute value: %d)",
        insn.operands[0].imm.value.u, insn.operands[0].imm.isRelative, value);
  }
  else {
    assert(false &&
      "add_branches shouldn't be called with an instruction that isn't a branch"
    );
  }

}

template <size_t address_size>
class zydis_architecture : public Architecture {
  using address_traits = address_traits<address_size>;

  ZydisDecoder _decoder;
  ZydisFormatter _formatter;

  // TODO Original formatter hooks

  ZydisFormatterFormatFunc _orig_print_prefixes = nullptr;
  ZydisFormatterFormatFunc _orig_print_mnemonic = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_reg = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_mem = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_ptr = nullptr;
  ZydisFormatterFormatOperandFunc _orig_format_operand_imm = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_operand_size = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_segment = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_decorator = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_displacement = nullptr;
  ZydisFormatterFormatOperandFunc _orig_print_immediate = nullptr;

  struct hook_data {
    hook_data(zydis_architecture<address_size>& arch,
              std::vector<InstructionTextToken>& instruction_text_tokens)
      : arch(arch),
        tokens(instruction_text_tokens) {
    }

    zydis_architecture<address_size>& arch;
    std::vector<InstructionTextToken>& tokens;
  };

  static ZydisStatus print_prefixes(const ZydisFormatter* /*unused*/,
                                    char** buffer,
                                    ZydisUSize buffer_len,
                                    const ZydisDecodedInstruction* insn,
                                    void* user_data) {
    auto* data = static_cast<hook_data*>(user_data);
  }

  static ZydisStatus print_mnemonic(const ZydisFormatter* /*unused*/,
                                    char** buffer,
                                    ZydisUSize buffer_len,
                                    const ZydisDecodedInstruction* insn,
                                    void* user_data) {

  }

  static ZydisStatus format_operand_reg(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus format_operand_mem(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus format_operand_ptr(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus format_operand_imm(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus print_operand_size(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus print_segment(const ZydisFormatter* /*unused*/,
                                   char** buffer,
                                   ZydisUSize buffer_len,
                                   const ZydisDecodedInstruction* insn,
                                   void* user_data) {

  }

  static ZydisStatus print_decorator(const ZydisFormatter* /*unused*/,
                                     char** buffer,
                                     ZydisUSize buffer_len,
                                     const ZydisDecodedInstruction* insn,
                                     void* user_data) {

  }

  static ZydisStatus print_displacement(const ZydisFormatter* /*unused*/,
                                        char** buffer,
                                        ZydisUSize buffer_len,
                                        const ZydisDecodedInstruction* insn,
                                        void* user_data) {

  }

  static ZydisStatus print_immediate(const ZydisFormatter* /*unused*/,
                                     char** buffer,
                                     ZydisUSize buffer_len,
                                     const ZydisDecodedInstruction* insn,
                                     void* user_data) {

  }

  bool set_formatter_hooks() {
    const void* c = nullptr;

#define SET_HOOK(h, f) \
  c = (const void*)(&f); \
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
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_DECORATOR, print_decorator);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_DISPLACEMENT, print_displacement);
    SET_HOOK(ZYDIS_FORMATTER_HOOK_PRINT_IMMEDIATE, print_immediate);

#undef SET_HOOK

    return true;
  }

public:
  zydis_architecture() : Architecture(address_traits::arch_name) {
    if (const auto status = ZydisDecoderInit(&_decoder,
                                             address_traits::machine_mode,
                                             address_traits::address_width);
      status != ZYDIS_STATUS_SUCCESS
    ) {
      throw std::runtime_error("Could not initialize the zydis decoder");
    }

    if (const auto status = ZydisFormatterInit(&_formatter,
                                               ZYDIS_FORMATTER_STYLE_INTEL);
      status != ZYDIS_STATUS_SUCCESS) {
      throw std::runtime_error("Could not initialize the zydis formatter");
    }

    if (!set_formatter_hooks()) {
      throw std::runtime_error("Could not set formatter hooks");
    }
  }

  size_t GetAddressSize() const override {
    return address_size;
  }

  size_t GetDefaultIntegerSize() const override {
    return GetAddressSize();
  }

  bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t max_len,
                          InstructionInfo& result) override {
    ZydisDecodedInstruction insn;
    CHECK_RESULT(ZydisDecoderDecodeBuffer(&_decoder, data, max_len, addr, &insn)
    );

    result.length = insn.length;
    Log(InfoLog, "Zydis instruciton length: %d", insn.length);

    if (is_branch(insn)) {
      add_branches(insn, result);
    }

    return true;
  }

  bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
                          std::vector<InstructionTextToken>& result) override {
    // TODO: How do we find the buffer length? Save it from GetInstructionInfo?

    size_t total_decoded = 0;
    ZydisDecodedInstruction insn;

    for (ZydisStatus r = ZYDIS_STATUS_SUCCESS; r == ZYDIS_STATUS_SUCCESS &&
         total_decoded <= len;
         r = ZydisDecoderDecodeBuffer(&_decoder, data + total_decoded, len,
                                      addr + total_decoded, &insn)) {
      total_decoded += insn.length;
    }

    /*ZydisDecodedInstruction insn;
    CHECK_RESULT(ZydisDecoderDecodeBuffer(&_decoder, data, len, addr, &insn)
    );

    Log(InfoLog, "Len: %d (global)", len);

    //len = insn.length;

    result.push_back(InstructionTextToken{ BNInstructionTextTokenType::KeywordToken, "ABC" });*/

    return true;
  }

  BNEndianness GetEndianness() const override {
    return LittleEndian;
  }
};

std::unordered_map<BinaryView*, Architecture*> original_architectures;

extern "C" {
  BINARYNINJAPLUGIN bool CorePluginInit() {
    auto* zydis_arch = new zydis_architecture<4>();
    Architecture::Register(zydis_arch);

    auto* zydis_x64_arch = new zydis_architecture<8>();
    Architecture::Register(zydis_x64_arch);

    PluginCommand::Register("Zydis x86",
                            "Use zydis for 32 bit ELF, PE and Mach-O files.",
                            [zydis_arch](BinaryView* view) {
                            BinaryViewType::RegisterArchitecture(
                              "ELF", 3, LittleEndian, zydis_arch);
                            BinaryViewType::RegisterArchitecture(
                              "PE", 0x14c, LittleEndian, zydis_arch);
                            BinaryViewType::RegisterArchitecture(
                              "Mach-O", 0x7, LittleEndian,
                              zydis_arch);
                          });

    PluginCommand::Register("Zydis x64",
                            "Use zydis for 64 bit ELF, and PE files.",
                            [zydis_x64_arch](BinaryView* view) {
                            BinaryViewType::RegisterArchitecture(
                              "ELF", 0x3E, LittleEndian, zydis_x64_arch);
                            BinaryViewType::RegisterArchitecture(
                              "PE", 0x8664, LittleEndian, zydis_x64_arch);
                          });

    // PE: 0x8664
    // ELF: 0x3E
    // no idea about Mach-o

    return true;
  }
};
