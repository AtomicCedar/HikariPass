//===- Opcode.h - VMP opcode / packing constants --------------------------===//
#ifndef _HIKARI_VMP_OPCODE_H_
#define _HIKARI_VMP_OPCODE_H_

#include <cstdint>

namespace hikari_vmp {

enum Op : uint8_t {
  OP_NOP = 0x00,
  OP_ALLOCA = 0x01,
  OP_LOAD = 0x02,
  OP_STORE = 0x03,
  OP_BINOP = 0x04,
  OP_ICMP = 0x05,
  OP_BR = 0x06,
  OP_RET = 0x07,
  OP_GEP = 0x08,
  OP_CALL = 0x09,
  OP_CAST = 0x0A,
  OP_SELECT = 0x0B,
  OP_FENCE = 0x0C,
  OP_ATOMICRMW = 0x0D,
  OP_UNREACHABLE = 0x0E,
  OP_CMPXCHG = 0x0F,
  OP_COPY = 0x10,
  OP_FBINOP = 0x11,
  OP_FCMP = 0x12,
  OP_FCAST = 0x13,
};

enum BinSubOp : uint8_t {
  BIN_ADD = 0x00,
  BIN_SUB = 0x01,
  BIN_MUL = 0x02,
  BIN_UDIV = 0x03,
  BIN_SDIV = 0x04,
  BIN_UREM = 0x05,
  BIN_SREM = 0x06,
  BIN_SHL = 0x07,
  BIN_LSHR = 0x08,
  BIN_ASHR = 0x09,
  BIN_AND = 0x0A,
  BIN_OR = 0x0B,
  BIN_XOR = 0x0C,
};

enum ICmpPred : uint8_t {
  ICMP_EQ = 0,
  ICMP_NE = 1,
  ICMP_UGT = 2,
  ICMP_UGE = 3,
  ICMP_ULT = 4,
  ICMP_ULE = 5,
  ICMP_SGT = 6,
  ICMP_SGE = 7,
  ICMP_SLT = 8,
  ICMP_SLE = 9,
};

enum CastKind : uint8_t {
  CAST_TRUNC = 0,
  CAST_ZEXT = 1,
  CAST_SEXT = 2,
  CAST_BITCAST = 3,
  CAST_PTRTOINT = 4,
  CAST_INTTOPTR = 5,
};

// AtomicRMW sub-op — mirrors LLVM's AtomicRMWInst::BinOp for the integer
// operations the VM supports (values shared with BIN_* where possible is
// NOT assumed; this enum is its own wire format).
enum RmwSubOp : uint8_t {
  RMW_XCHG = 0,
  RMW_ADD = 1,
  RMW_SUB = 2,
  RMW_AND = 3,
  RMW_OR = 4,
  RMW_XOR = 5,
  RMW_NAND = 6,
  RMW_MAX = 7,
  RMW_MIN = 8,
  RMW_UMAX = 9,
  RMW_UMIN = 10,
};

// Float binop sub-ops (wire format; values shared with FCmp preds are NOT
// assumed).  Operands/results are IEEE-754 bit patterns in data slots.
enum FBinSubOp : uint8_t {
  FB_ADD = 0,
  FB_SUB = 1,
  FB_MUL = 2,
  FB_DIV = 3,
};

// Float cast kinds.
enum FCastKind : uint8_t {
  FC_FPEXT = 0,   // float -> double
  FC_FPTRUNC = 1, // double -> float
  FC_SITOFP = 2,  // int -> float/double (dest size picks)
  FC_FPTOSI = 3,  // float/double -> int (dest size picks)
  FC_FPTOUI = 4,
  FC_UITOFP = 5,
};

static constexpr unsigned kPointerSize = 8;

} // namespace hikari_vmp

#endif
