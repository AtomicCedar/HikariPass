//===- Virtualization.cpp - LLVM IR Virtualization (VMP) Pass -------------===//
//
// IR-level VMP for Hikari (phase 1+):
//   translate supported IR → bytecode, rewrite function as VM launcher.
//
// Annotation: "vmp" | CLI: enable-vmp | Env: VMP=1
// Not part of enable-allobf.
//
//===----------------------------------------------------------------------===//

#include "include/Virtualization.h"
#include "include/CryptoUtils.h"
#include "include/Flattening.h"
#include "include/Utils.h"
#include "vmp/Opcode.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"

#include <map>
#include <optional>
#include <random>
#include <vector>

using namespace llvm;
using namespace hikari_vmp;

static cl::opt<bool> VmpEncrypt(
    "vmp-encrypt", cl::init(true), cl::NotHidden,
    cl::desc("Enable L1 dual-seed bytecode encryption for VMP"));
static cl::opt<bool> VmpHarden(
    "vmp-harden", cl::init(false), cl::NotHidden,
    cl::desc("Run CFF on VMP interpreter body after build"));

static void loadVmpEnv() {
  if (const char *E = getenv("VMPNOENC"))
    if (E[0] != '\0' && E[0] != '0')
      VmpEncrypt = false;
  if (const char *E = getenv("VMPENCRYPT"))
    if (E[0] != '\0' && E[0] != '0')
      VmpEncrypt = true;
  if (const char *E = getenv("VMPHARDEN"))
    if (E[0] != '\0' && E[0] != '0')
      VmpHarden = true;
}

namespace {

// ---- PRNG / bytecode helpers ------------------------------------------------

static uint32_t xorshift32(uint32_t *State) {
  uint32_t X = *State ? *State : 0xA5A5A5A5u;
  X ^= X << 13;
  X ^= X >> 17;
  X ^= X << 5;
  *State = X;
  return X;
}

static uint32_t nonzeroSeed() {
  uint32_t S = cryptoutils->get_uint32_t();
  return S ? S : 0xC0FFEEu;
}

static void emitU8(std::vector<uint8_t> &C, uint8_t V) { C.push_back(V); }

static void emitU64(std::vector<uint8_t> &C, uint64_t V) {
  for (unsigned I = 0; I < 8; ++I)
    C.push_back(static_cast<uint8_t>((V >> (8 * I)) & 0xFF));
}

static void emitPackedConst(std::vector<uint8_t> &C, uint8_t Size,
                            uint64_t Val) {
  emitU8(C, Size);
  emitU8(C, 1); // constant
  for (unsigned I = 0; I < Size; ++I)
    C.push_back(static_cast<uint8_t>((Val >> (8 * I)) & 0xFF));
}

static void emitPackedVar(std::vector<uint8_t> &C, uint8_t Size, uint64_t Off) {
  emitU8(C, Size);
  emitU8(C, 0); // variable
  emitU64(C, Off);
}

// Deterministic per-function PRNG: derives a stream from the function name so
// opcode mappings / fake-instruction placement stay stable under HIKARI_SEED.
static uint32_t fnHashSeed(StringRef Name) {
  uint32_t H = 0x811C9DC5u; // FNV-1a
  for (char Ch : Name) {
    H ^= static_cast<uint8_t>(Ch);
    H *= 0x01000193u;
  }
  // Mix in the global seed so HIKARI_SEED changes every derived stream.
  uint32_t G = 0;
  if (const char *E = getenv("HIKARI_SEED"))
    G = static_cast<uint32_t>(strtoull(E, nullptr, 0));
  G ^= H;
  G ^= G >> 16;
  G *= 0x7FEB4CE6u;
  G ^= G >> 15;
  return G ? G : 0x9E3779B9u;
}

static uint32_t fnNext(uint32_t *State) { return xorshift32(State); }

// Runtime-encodable mask replay: mask(n) = the (n+1)-th draw of the stream
// seeded by Seed0.  The compiler-side emitter uses the same function so the
// constants in vmp_seeds_ match what SeedReloadFn recovers.
static uint32_t maskReplay(uint32_t Seed0, uint32_t N) {
  uint32_t S = Seed0;
  uint32_t V = 0;
  for (uint32_t I = 0; I <= N; ++I)
    V = fnNext(&S);
  return V;
}

// ---- translate context ------------------------------------------------------

struct CallArgInfo {
  bool IsConst = false;
  uint64_t ConstVal = 0;
  uint32_t Off = 0;
  Type *Ty = nullptr;
  uint8_t Size = 0;
};

struct CallSiteInfo {
  uint64_t Id = 0;
  Function *DirectCallee = nullptr; // nullptr => indirect
  uint32_t CalleeOff = 0;           // data_off of fn ptr when indirect
  FunctionType *FTy = nullptr;
  Type *RetTy = nullptr;
  uint32_t RetOff = 0;
  bool HasRet = false;
  std::vector<CallArgInfo> Args;
};

struct GlobalSlot {
  GlobalValue *GV = nullptr;
  uint32_t Off = 0;
};

struct BBSeedInfo {
  uint32_t EntryIP = 0;
  uint32_t EndIP = 0; // exclusive
  uint32_t OpcodeSeed = 0;
  uint32_t CodeSeed = 0;
  std::vector<uint32_t> OpcodeOffsets;
};

struct VMPContext {
  Function *F = nullptr;
  Module *M = nullptr;
  const DataLayout *DL = nullptr;
  std::vector<uint8_t> Code;
  std::map<Value *, uint32_t> ValueMap;
  std::map<BasicBlock *, uint32_t> BBMap;
  std::vector<std::pair<uint32_t, BasicBlock *>> BrPatches;
  std::vector<CallSiteInfo> Calls;
  std::vector<GlobalSlot> Globals;
  std::vector<BBSeedInfo> BBSeeds;
  BBSeedInfo *CurBB = nullptr;
  uint32_t DataSize = 0;
  uint64_t NextCallId = 0;
  bool Encrypt = true;
  bool Failed = false;
  std::string FailReason;
  // Per-function opcode mapping: wire[k] = the byte value that stands for
  // Opcode k in this function's bytecode.  Derived from the function name and
  // HIKARI_SEED so every function (and every build) gets a unique encoding.
  uint8_t WireOp[16] = {0};
  bool FakeInst = true;
  uint32_t FakeState = 0;

  void initOpcodeMap(StringRef FName) {
    uint32_t S = fnHashSeed(FName);
    // wire value for opcode k: k-th draw from a shuffled 1..255 space, mapped
    // through xorshift to spread bits.  OP_NOP (0) stays 0 so encrypted-garbage
    // zero bytes still land on the safe no-op.
    bool Used[256] = {false};
    Used[0] = true;
    WireOp[0] = 0;
    for (unsigned K = 1; K < 16; ++K) {
      uint8_t V;
      do {
        V = static_cast<uint8_t>(fnNext(&S) & 0xFF);
      } while (Used[V]);
      Used[V] = true;
      WireOp[K] = V;
    }
    FakeState = fnNext(&S);
  }

  uint8_t op(uint8_t K) const { return WireOp[K]; }

  void fail(const Twine &M) {
    Failed = true;
    FailReason = M.str();
  }

  void emitOp(uint8_t K) {
    if (CurBB)
      CurBB->OpcodeOffsets.push_back(static_cast<uint32_t>(Code.size()));
    emitU8(Code, op(K));
    // Fake-instruction injection: with a deterministic per-function chance,
    // emit OP_NOP after a real opcode.  The interpreter skips it for free and
    // decoders can no longer assume opcode positions line up with instructions.
    if (FakeInst && K != 0 && (fnNext(&FakeState) & 3) == 0) {
      if (CurBB)
        CurBB->OpcodeOffsets.push_back(static_cast<uint32_t>(Code.size()));
      emitU8(Code, op(0));
    }
  }

  uint32_t typeSize(Type *Ty) const {
    if (Ty->isPointerTy())
      return kPointerSize;
    return static_cast<uint32_t>(DL->getTypeAllocSize(Ty));
  }

  Align typeAlign(Type *Ty) const {
    if (Ty->isPointerTy())
      return Align(kPointerSize);
    return DL->getABITypeAlign(Ty);
  }

  uint32_t allocSlot(uint32_t Size, Align A = Align(1)) {
    uint32_t Off = static_cast<uint32_t>(alignTo(DataSize, A.value()));
    DataSize = Off + Size;
    return Off;
  }

  bool has(Value *V) const { return ValueMap.count(V) != 0; }
  uint32_t off(Value *V) const { return ValueMap.at(V); }
  void map(Value *V, uint32_t O) { ValueMap[V] = O; }
};

static bool isIntOK(Type *Ty) {
  if (!Ty->isIntegerTy())
    return false;
  unsigned W = Ty->getIntegerBitWidth();
  return W == 1 || W == 8 || W == 16 || W == 32 || W == 64;
}

static bool isTypeOK(Type *Ty) {
  return Ty->isVoidTy() || Ty->isPointerTy() || isIntOK(Ty);
}

static std::optional<uint8_t> mapBin(unsigned Op) {
  switch (Op) {
  case Instruction::Add:  return BIN_ADD;
  case Instruction::Sub:  return BIN_SUB;
  case Instruction::Mul:  return BIN_MUL;
  case Instruction::UDiv: return BIN_UDIV;
  case Instruction::SDiv: return BIN_SDIV;
  case Instruction::URem: return BIN_UREM;
  case Instruction::SRem: return BIN_SREM;
  case Instruction::Shl:  return BIN_SHL;
  case Instruction::LShr: return BIN_LSHR;
  case Instruction::AShr: return BIN_ASHR;
  case Instruction::And:  return BIN_AND;
  case Instruction::Or:   return BIN_OR;
  case Instruction::Xor:  return BIN_XOR;
  default: return std::nullopt;
  }
}

static std::optional<uint8_t> mapPred(CmpInst::Predicate P) {
  switch (P) {
  case CmpInst::ICMP_EQ:  return ICMP_EQ;
  case CmpInst::ICMP_NE:  return ICMP_NE;
  case CmpInst::ICMP_UGT: return ICMP_UGT;
  case CmpInst::ICMP_UGE: return ICMP_UGE;
  case CmpInst::ICMP_ULT: return ICMP_ULT;
  case CmpInst::ICMP_ULE: return ICMP_ULE;
  case CmpInst::ICMP_SGT: return ICMP_SGT;
  case CmpInst::ICMP_SGE: return ICMP_SGE;
  case CmpInst::ICMP_SLT: return ICMP_SLT;
  case CmpInst::ICMP_SLE: return ICMP_SLE;
  default: return std::nullopt;
  }
}

static std::optional<uint8_t> mapCast(unsigned Op) {
  switch (Op) {
  case Instruction::Trunc:    return CAST_TRUNC;
  case Instruction::ZExt:     return CAST_ZEXT;
  case Instruction::SExt:     return CAST_SEXT;
  case Instruction::BitCast:  return CAST_BITCAST;
  case Instruction::PtrToInt: return CAST_PTRTOINT;
  case Instruction::IntToPtr: return CAST_INTTOPTR;
  default: return std::nullopt;
  }
}

static void ensureGlobalMapped(VMPContext &C, GlobalValue *GV) {
  if (C.has(GV))
    return;
  uint32_t Off = C.allocSlot(kPointerSize, Align(kPointerSize));
  C.map(GV, Off);
  C.Globals.push_back({GV, Off});
}

static void emitOperand(VMPContext &C, Value *V) {
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    uint8_t Sz = static_cast<uint8_t>(std::max(1u, C.typeSize(CI->getType())));
    emitPackedConst(C.Code, Sz, CI->getZExtValue());
    return;
  }
  if (isa<ConstantPointerNull>(V)) {
    emitPackedConst(C.Code, kPointerSize, 0);
    return;
  }
  if (auto *GV = dyn_cast<GlobalVariable>(V)) {
    ensureGlobalMapped(C, GV);
    emitPackedVar(C.Code, kPointerSize, C.off(GV));
    return;
  }
  if (auto *Fn = dyn_cast<Function>(V)) {
    ensureGlobalMapped(C, Fn);
    emitPackedVar(C.Code, kPointerSize, C.off(Fn));
    return;
  }
  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    C.fail("residual ConstantExpr operand");
    emitPackedVar(C.Code, 8, 0);
    (void)CE;
    return;
  }
  if (!C.has(V)) {
    C.fail("operand not mapped");
    emitPackedVar(C.Code, 8, 0);
    return;
  }
  uint8_t Sz = static_cast<uint8_t>(std::max(1u, C.typeSize(V->getType())));
  emitPackedVar(C.Code, Sz, C.off(V));
}

static CallArgInfo captureArg(VMPContext &C, Value *V) {
  CallArgInfo A;
  A.Ty = V->getType();
  A.Size = static_cast<uint8_t>(std::max(1u, C.typeSize(V->getType())));
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    A.IsConst = true;
    A.ConstVal = CI->getZExtValue();
    return A;
  }
  if (isa<ConstantPointerNull>(V)) {
    A.IsConst = true;
    A.ConstVal = 0;
    return A;
  }
  if (auto *GV = dyn_cast<GlobalValue>(V)) {
    ensureGlobalMapped(C, GV);
    A.IsConst = false;
    A.Off = C.off(GV);
    return A;
  }
  if (!C.has(V)) {
    C.fail("call arg not mapped");
    A.IsConst = true;
    A.ConstVal = 0;
    return A;
  }
  A.IsConst = false;
  A.Off = C.off(V);
  return A;
}

static bool isIgnorableIntrinsic(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  if (!Callee || !Callee->isIntrinsic())
    return false;
  switch (Callee->getIntrinsicID()) {
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_value:
  case Intrinsic::dbg_assign:
  case Intrinsic::dbg_label:
  case Intrinsic::lifetime_start:
  case Intrinsic::lifetime_end:
  case Intrinsic::assume:
  case Intrinsic::experimental_noalias_scope_decl:
  case Intrinsic::donothing:
    return true;
  default:
    return false;
  }
}

static bool translateInst(VMPContext &C, Instruction *I) {
  if (auto *AI = dyn_cast<AllocaInst>(I)) {
    if (AI->isArrayAllocation())
      return C.fail("array alloca"), false;
    Type *AT = AI->getAllocatedType();
    uint32_t Res = C.allocSlot(kPointerSize, Align(kPointerSize));
    C.map(AI, Res);
    uint32_t AreaSz = std::max(1u, C.typeSize(AT));
    // For non-simple types use DL size; allow i32/ptr/struct raw bytes
    uint32_t Area = C.allocSlot(AreaSz, C.typeAlign(AT));
    C.emitOp(OP_ALLOCA);
    emitPackedVar(C.Code, kPointerSize, Res);
    emitU64(C.Code, Area);
    return true;
  }

  if (auto *LI = dyn_cast<LoadInst>(I)) {
    if (LI->isAtomic() || LI->isVolatile() || !isTypeOK(LI->getType()))
      return C.fail("bad load"), false;
    uint32_t Sz = C.typeSize(LI->getType());
    uint32_t Res = C.allocSlot(Sz, C.typeAlign(LI->getType()));
    C.map(LI, Res);
    C.emitOp(OP_LOAD);
    emitPackedVar(C.Code, static_cast<uint8_t>(Sz), Res);
    emitOperand(C, LI->getPointerOperand());
    return true;
  }

  if (auto *SI = dyn_cast<StoreInst>(I)) {
    if (SI->isAtomic() || SI->isVolatile() ||
        !isTypeOK(SI->getValueOperand()->getType()))
      return C.fail("bad store"), false;
    C.emitOp(OP_STORE);
    emitOperand(C, SI->getValueOperand());
    emitOperand(C, SI->getPointerOperand());
    return true;
  }

  if (auto *BO = dyn_cast<BinaryOperator>(I)) {
    auto Sub = mapBin(BO->getOpcode());
    if (!Sub || !isIntOK(BO->getType()))
      return C.fail("bad binop"), false;
    uint32_t Sz = C.typeSize(BO->getType());
    uint32_t Res = C.allocSlot(Sz, C.typeAlign(BO->getType()));
    C.map(BO, Res);
    C.emitOp(OP_BINOP);
    emitU8(C.Code, *Sub);
    emitPackedVar(C.Code, static_cast<uint8_t>(Sz), Res);
    emitOperand(C, BO->getOperand(0));
    emitOperand(C, BO->getOperand(1));
    return true;
  }

  if (auto *IC = dyn_cast<ICmpInst>(I)) {
    auto P = mapPred(IC->getPredicate());
    if (!P)
      return C.fail("bad icmp"), false;
    uint32_t Res = C.allocSlot(1, Align(1));
    C.map(IC, Res);
    C.emitOp(OP_ICMP);
    emitU8(C.Code, *P);
    emitPackedVar(C.Code, 1, Res);
    emitOperand(C, IC->getOperand(0));
    emitOperand(C, IC->getOperand(1));
    return true;
  }

  if (auto *BR = dyn_cast<BranchInst>(I)) {
    C.emitOp(OP_BR);
    if (BR->isUnconditional()) {
      emitU8(C.Code, 0);
      uint32_t At = static_cast<uint32_t>(C.Code.size());
      emitU64(C.Code, 0);
      C.BrPatches.emplace_back(At, BR->getSuccessor(0));
    } else {
      emitU8(C.Code, 1);
      emitOperand(C, BR->getCondition());
      uint32_t AtT = static_cast<uint32_t>(C.Code.size());
      emitU64(C.Code, 0);
      C.BrPatches.emplace_back(AtT, BR->getSuccessor(0));
      uint32_t AtF = static_cast<uint32_t>(C.Code.size());
      emitU64(C.Code, 0);
      C.BrPatches.emplace_back(AtF, BR->getSuccessor(1));
    }
    return true;
  }

  if (auto *RI = dyn_cast<ReturnInst>(I)) {
    C.emitOp(OP_RET);
    if (Value *RV = RI->getReturnValue()) {
      emitU8(C.Code, 1);
      emitOperand(C, RV);
    } else {
      emitU8(C.Code, 0);
    }
    return true;
  }

  if (auto *CI = dyn_cast<CastInst>(I)) {
    auto K = mapCast(CI->getOpcode());
    if (!K || !isTypeOK(CI->getType()) || !isTypeOK(CI->getSrcTy()))
      return C.fail("bad cast"), false;
    uint32_t Sz = C.typeSize(CI->getType());
    uint32_t Res = C.allocSlot(Sz, C.typeAlign(CI->getType()));
    C.map(CI, Res);
    C.emitOp(OP_CAST);
    emitU8(C.Code, *K);
    emitPackedVar(C.Code, static_cast<uint8_t>(Sz), Res);
    emitOperand(C, CI->getOperand(0));
    return true;
  }

  if (auto *SI = dyn_cast<SelectInst>(I)) {
    if (!isTypeOK(SI->getType()))
      return C.fail("bad select"), false;
    uint32_t Sz = C.typeSize(SI->getType());
    uint32_t Res = C.allocSlot(Sz, C.typeAlign(SI->getType()));
    C.map(SI, Res);
    C.emitOp(OP_SELECT);
    emitPackedVar(C.Code, static_cast<uint8_t>(Sz), Res);
    emitOperand(C, SI->getCondition());
    emitOperand(C, SI->getTrueValue());
    emitOperand(C, SI->getFalseValue());
    return true;
  }

  if (isa<UnreachableInst>(I)) {
    C.emitOp(OP_UNREACHABLE);
    return true;
  }

  if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
    uint32_t Res = C.allocSlot(kPointerSize, Align(kPointerSize));
    C.map(GEP, Res);

    // kind 0: result = base + byte_offset (const or runtime bytes)
    // kind 1: result = base + index * elem_size
    APInt ConstOff(C.DL->getIndexSizeInBits(GEP->getPointerAddressSpace()), 0);
    if (GEP->accumulateConstantOffset(*C.DL, ConstOff)) {
      C.emitOp(OP_GEP);
      emitU8(C.Code, 0); // kind: byte offset
      emitU64(C.Code, 0); // elem_size unused
      emitPackedVar(C.Code, kPointerSize, Res);
      emitOperand(C, GEP->getPointerOperand());
      // A byte offset is signed.  ConstOff is only index-sized (32-bit on
      // 32-bit targets), so zero-extending it to pointer width would turn
      // `p - 1` into `p + 0xFFFFFFFF`.
      emitPackedConst(C.Code, kPointerSize,
                      static_cast<uint64_t>(ConstOff.getSExtValue()));
      return true;
    }

    if (GEP->getNumIndices() == 1) {
      Type *Src = GEP->getSourceElementType();
      uint64_t ElemSz = C.DL->getTypeAllocSize(Src);
      C.emitOp(OP_GEP);
      emitU8(C.Code, 1);
      emitU64(C.Code, ElemSz);
      emitPackedVar(C.Code, kPointerSize, Res);
      emitOperand(C, GEP->getPointerOperand());
      emitOperand(C, GEP->getOperand(1));
      return true;
    }

    // getelementptr Ty, ptr, i64 0, <idx>  (common O0 array form)
    if (GEP->getNumIndices() == 2) {
      if (auto *First = dyn_cast<ConstantInt>(GEP->getOperand(1))) {
        if (First->isZero()) {
          Type *Indexed = GetElementPtrInst::getIndexedType(
              GEP->getSourceElementType(), {GEP->getOperand(1)});
          if (!Indexed)
            return C.fail("gep indexed type"), false;
          // After first 0, second index scales by sizeof(result element)
          // For [N x T], index 0 yields [N x T] in-place; second scales T.
          // Use type at last index:
          Type *LastTy = GetElementPtrInst::getIndexedType(
              GEP->getSourceElementType(),
              {GEP->getOperand(1), ConstantInt::get(GEP->getOperand(2)->getType(), 0)});
          // Simpler: getResultElementType when available
          Type *ElemTy = GEP->getResultElementType();
          uint64_t ElemSz = C.DL->getTypeAllocSize(ElemTy);
          (void)Indexed;
          (void)LastTy;
          C.emitOp(OP_GEP);
          emitU8(C.Code, 1);
          emitU64(C.Code, ElemSz);
          emitPackedVar(C.Code, kPointerSize, Res);
          emitOperand(C, GEP->getPointerOperand());
          emitOperand(C, GEP->getOperand(2));
          return true;
        }
      }
    }

    return C.fail("complex gep"), false;
  }

  if (auto *CB = dyn_cast<CallBase>(I)) {
    if (isIgnorableIntrinsic(CB))
      return true;
    if (isa<InvokeInst>(CB))
      return C.fail("invoke"), false;
    if (CB->isMustTailCall())
      return C.fail("musttail"), false;

    // Only direct calls to known functions, or indirect with mapped callee value.
    CallSiteInfo CS;
    CS.Id = C.NextCallId++;
    CS.FTy = CB->getFunctionType();
    CS.RetTy = CB->getType();
    CS.HasRet = !CB->getType()->isVoidTy();
    if (CS.HasRet) {
      if (!isTypeOK(CS.RetTy))
        return C.fail("call ret type"), false;
      CS.RetOff = C.allocSlot(C.typeSize(CS.RetTy), C.typeAlign(CS.RetTy));
      C.map(CB, CS.RetOff);
    }

    if (Function *Callee = CB->getCalledFunction()) {
      if (Callee->isIntrinsic() && !isIgnorableIntrinsic(CB))
        return C.fail("unsupported intrinsic call"), false;
      CS.DirectCallee = Callee;
    } else {
      Value *CV = CB->getCalledOperand()->stripPointerCasts();
      if (auto *Fn = dyn_cast<Function>(CV)) {
        CS.DirectCallee = Fn;
      } else {
        if (!C.has(CV) && !isa<GlobalValue>(CV))
          return C.fail("indirect call target unmapped"), false;
        if (auto *GV = dyn_cast<GlobalValue>(CV))
          ensureGlobalMapped(C, GV);
        if (!C.has(CV))
          return C.fail("indirect call target"), false;
        CS.DirectCallee = nullptr;
        CS.CalleeOff = C.off(CV);
      }
    }

    for (unsigned I = 0, E = CB->arg_size(); I != E; ++I) {
      Value *Arg = CB->getArgOperand(I);
      if (!isTypeOK(Arg->getType()) && !Arg->getType()->isPointerTy())
        return C.fail("call arg type"), false;
      // Aggregate arguments (byval / small-struct passing) have no slot
      // encoding here; passing them through produced wrong loads.  Refuse
      // cleanly so the function is skipped instead of miscompiled.
      if (Arg->getType()->isAggregateType())
        return C.fail("aggregate call arg"), false;
      CS.Args.push_back(captureArg(C, Arg));
      if (C.Failed)
        return false;
    }

    C.emitOp(OP_CALL);
    emitU64(C.Code, CS.Id);
    C.Calls.push_back(std::move(CS));
    return true;
  }

  if (isa<PHINode>(I))
    return C.fail("phi remains"), false;

  return C.fail(std::string("unsupported: ") + I->getOpcodeName()), false;
}

static void encryptBytecode(VMPContext &C) {
  if (!C.Encrypt)
    return;
  for (BBSeedInfo &BB : C.BBSeeds) {
    // 1) opcode-layer XOR only on opcode bytes
    uint32_t OpSt = BB.OpcodeSeed;
    for (uint32_t Off : BB.OpcodeOffsets) {
      if (Off < C.Code.size())
        C.Code[Off] ^= static_cast<uint8_t>(xorshift32(&OpSt) & 0xFF);
    }
    // 2) code-layer XOR on entire BB range
    uint32_t CdSt = BB.CodeSeed;
    for (uint32_t I = BB.EntryIP; I < BB.EndIP && I < C.Code.size(); ++I)
      C.Code[I] ^= static_cast<uint8_t>(xorshift32(&CdSt) & 0xFF);
  }
}

static bool translateFunction(VMPContext &C) {
  Function *F = C.F;
  if (!F->getReturnType()->isVoidTy()) {
    if (!isTypeOK(F->getReturnType()))
      return C.fail("bad ret type"), false;
    C.allocSlot(C.typeSize(F->getReturnType()),
                C.typeAlign(F->getReturnType()));
  }
  for (Argument &A : F->args()) {
    if (!isTypeOK(A.getType()))
      return C.fail("bad arg type"), false;
    C.map(&A, C.allocSlot(C.typeSize(A.getType()), C.typeAlign(A.getType())));
  }
  for (BasicBlock &BB : *F) {
    BBSeedInfo Info;
    Info.EntryIP = static_cast<uint32_t>(C.Code.size());
    Info.OpcodeSeed = nonzeroSeed();
    Info.CodeSeed = nonzeroSeed();
    C.BBSeeds.push_back(Info);
    C.CurBB = &C.BBSeeds.back();
    C.BBMap[&BB] = Info.EntryIP;
    for (Instruction &I : BB) {
      if (C.Failed || !translateInst(C, &I))
        return false;
    }
    C.CurBB->EndIP = static_cast<uint32_t>(C.Code.size());
    C.CurBB = nullptr;
  }
  // Fix BR targets while still plaintext.
  for (auto &P : C.BrPatches) {
    auto It = C.BBMap.find(P.second);
    if (It == C.BBMap.end())
      return C.fail("bad br target"), false;
    uint64_t T = It->second;
    for (unsigned I = 0; I < 8; ++I)
      C.Code[P.first + I] = static_cast<uint8_t>((T >> (8 * I)) & 0xFF);
  }
  if (C.Code.empty())
    return C.fail("empty code"), false;
  encryptBytecode(C);
  return !C.Failed;
}

// ---- IR helpers for interpreter --------------------------------------------

// Inline xorshift32 on a stack i32 state slot; returns key byte (zext to i8).
static Value *irXorShiftKey(IRBuilder<> &B, Type *I8, Type *I32,
                            AllocaInst *StateSlot) {
  Value *X = B.CreateLoad(I32, StateSlot);
  // if zero, use fallback constant (should not happen with good seeds)
  Value *Is0 = B.CreateICmpEQ(X, ConstantInt::get(I32, 0));
  X = B.CreateSelect(Is0, ConstantInt::get(I32, 0xA5A5A5A5u), X);
  X = B.CreateXor(X, B.CreateShl(X, ConstantInt::get(I32, 13)));
  X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 17)));
  X = B.CreateXor(X, B.CreateShl(X, ConstantInt::get(I32, 5)));
  B.CreateStore(X, StateSlot);
  return B.CreateTrunc(X, I8);
}

// Read one code byte and undo code-layer XOR when Encrypt enabled (CodeState!=null).
static Value *irGetByte(IRBuilder<> &B, Type *I8, Type *I32, Value *Code,
                        AllocaInst *IP, AllocaInst *CodeState) {
  Value *Cur = B.CreateLoad(I32, IP);
  Value *P = B.CreateGEP(I8, Code, Cur);
  Value *Byte = B.CreateLoad(I8, P);
  B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(I32, 1)), IP);
  if (CodeState)
    Byte = B.CreateXor(Byte, irXorShiftKey(B, I8, I32, CodeState));
  return Byte;
}

static Value *irFetchOp(IRBuilder<> &B, Type *I8, Type *I32, Value *Code,
                        AllocaInst *IP, AllocaInst *CodeState,
                        AllocaInst *OpState) {
  Value *Byte = irGetByte(B, I8, I32, Code, IP, CodeState);
  if (OpState)
    Byte = B.CreateXor(Byte, irXorShiftKey(B, I8, I32, OpState));
  return Byte;
}

static Value *irGetU64(IRBuilder<> &B, Type *I8, Type *I32, Type *I64,
                       Value *Code, AllocaInst *IP, AllocaInst *CodeState) {
  Value *Acc = ConstantInt::get(I64, 0);
  for (unsigned I = 0; I < 8; ++I) {
    Value *Byte = irGetByte(B, I8, I32, Code, IP, CodeState);
    Acc = B.CreateOr(Acc, B.CreateShl(B.CreateZExt(Byte, I64),
                                      ConstantInt::get(I64, 8ull * I)));
  }
  return Acc;
}

static Value *irLoadBytes(IRBuilder<> &B, Type *I8, Type *I64, Value *Base,
                          Value *Off, Value *SizeI8) {
  Value *Acc = ConstantInt::get(I64, 0);
  for (unsigned I = 0; I < 8; ++I) {
    Value *Take = B.CreateICmpUGT(SizeI8, ConstantInt::get(I8, I));
    Value *P =
        B.CreateGEP(I8, Base, B.CreateAdd(Off, ConstantInt::get(I64, I)));
    Value *Byte = B.CreateLoad(I8, P);
    Value *Part =
        B.CreateShl(B.CreateZExt(Byte, I64), ConstantInt::get(I64, 8ull * I));
    Acc = B.CreateOr(Acc,
                     B.CreateSelect(Take, Part, ConstantInt::get(I64, 0)));
  }
  return Acc;
}

static void irStoreBytes(IRBuilder<> &B, Type *I8, Type *I64, Value *Base,
                         Value *Off, Value *Val, Value *SizeI8) {
  for (unsigned I = 0; I < 8; ++I) {
    Value *Take = B.CreateICmpUGT(SizeI8, ConstantInt::get(I8, I));
    Value *Byte =
        B.CreateTrunc(B.CreateLShr(Val, ConstantInt::get(I64, 8ull * I)), I8);
    Value *P =
        B.CreateGEP(I8, Base, B.CreateAdd(Off, ConstantInt::get(I64, I)));
    Value *Old = B.CreateLoad(I8, P);
    B.CreateStore(B.CreateSelect(Take, Byte, Old), P);
  }
}

static Value *irLoadMem(IRBuilder<> &B, Type *I8, Type *I64, Type *I8Ptr,
                        Value *AddrI64, Value *SizeI8) {
  Value *Addr = B.CreateIntToPtr(AddrI64, I8Ptr);
  return irLoadBytes(B, I8, I64, Addr, ConstantInt::get(I64, 0), SizeI8);
}

static void irStoreMem(IRBuilder<> &B, Type *I8, Type *I64, Type *I8Ptr,
                       Value *AddrI64, Value *Val, Value *SizeI8) {
  Value *Addr = B.CreateIntToPtr(AddrI64, I8Ptr);
  irStoreBytes(B, I8, I64, Addr, ConstantInt::get(I64, 0), Val, SizeI8);
}

// Sign-extend V from the low SizeI8 bytes into a full i64.
static Value *sextToI64(IRBuilder<> &B, Type *I8, Type *I64, Value *V,
                        Value *SizeI8) {
  Value *Full = B.CreateICmpUGE(SizeI8, ConstantInt::get(I8, 8));
  Value *Bits =
      B.CreateShl(B.CreateZExt(SizeI8, I64), ConstantInt::get(I64, 3));
  Value *Shift = B.CreateSub(ConstantInt::get(I64, 64), Bits);
  // Avoid UB when size==8 (shift 0 path taken via select).
  Value *Sext = B.CreateAShr(B.CreateShl(V, Shift), Shift);
  return B.CreateSelect(Full, V, Sext);
}

// Build vmp_eval_F(code*, ip*, data*, size_out*, code_state*) -> i64
static Function *buildEvalFn(Module *M, Function *Host, Type *I8, Type *I32,
                             Type *I64, Type *I8Ptr, bool Encrypt) {
  LLVMContext &Ctx = M->getContext();
  Type *P = PointerType::get(Ctx, 0);
  FunctionType *FT =
      FunctionType::get(I64, {I8Ptr, P, I8Ptr, P, P}, false);
  Function *Fn = Function::Create(FT, GlobalValue::InternalLinkage,
                                  Twine("vmp_eval_") + Host->getName(), M);
  writeAnnotationMetadata(Fn, "novmp");
  auto A = Fn->arg_begin();
  Value *Code = &*A++;
  Value *IPArg = &*A++;
  Value *Data = &*A++;
  Value *SizeOut = &*A++;
  Value *CodeStateArg = &*A++;

  auto *Entry = BasicBlock::Create(Ctx, "", Fn);
  auto *VarBB = BasicBlock::Create(Ctx, "", Fn);
  auto *CstBB = BasicBlock::Create(Ctx, "", Fn);
  auto *CLoop = BasicBlock::Create(Ctx, "", Fn);
  auto *CBody = BasicBlock::Create(Ctx, "", Fn);
  auto *CDone = BasicBlock::Create(Ctx, "", Fn);

  IRBuilder<> B(Entry);
  auto getByte = [&](IRBuilder<> &IB) -> Value * {
    Value *Cur = IB.CreateLoad(I32, IPArg);
    Value *Ptr = IB.CreateGEP(I8, Code, Cur);
    Value *Byte = IB.CreateLoad(I8, Ptr);
    IB.CreateStore(IB.CreateAdd(Cur, ConstantInt::get(I32, 1)), IPArg);
    if (Encrypt) {
      Value *X = IB.CreateLoad(I32, CodeStateArg);
      Value *Is0 = IB.CreateICmpEQ(X, ConstantInt::get(I32, 0));
      X = IB.CreateSelect(Is0, ConstantInt::get(I32, 0xA5A5A5A5u), X);
      X = IB.CreateXor(X, IB.CreateShl(X, ConstantInt::get(I32, 13)));
      X = IB.CreateXor(X, IB.CreateLShr(X, ConstantInt::get(I32, 17)));
      X = IB.CreateXor(X, IB.CreateShl(X, ConstantInt::get(I32, 5)));
      IB.CreateStore(X, CodeStateArg);
      Byte = IB.CreateXor(Byte, IB.CreateTrunc(X, I8));
    }
    return Byte;
  };
  auto getU64 = [&](IRBuilder<> &IB) -> Value * {
    Value *Acc = ConstantInt::get(I64, 0);
    for (unsigned I = 0; I < 8; ++I) {
      Value *Byte = getByte(IB);
      Acc = IB.CreateOr(Acc, IB.CreateShl(IB.CreateZExt(Byte, I64),
                                          ConstantInt::get(I64, 8ull * I)));
    }
    return Acc;
  };

  AllocaInst *SzA = B.CreateAlloca(I8);
  Value *Sz = getByte(B);
  Value *Tid = getByte(B);
  B.CreateStore(Sz, SzA);
  B.CreateStore(Sz, SizeOut);
  B.CreateCondBr(B.CreateICmpEQ(Tid, ConstantInt::get(I8, 0)), VarBB, CstBB);

  IRBuilder<> VB(VarBB);
  Value *Off = getU64(VB);
  VB.CreateRet(irLoadBytes(VB, I8, I64, Data, Off, VB.CreateLoad(I8, SzA)));

  IRBuilder<> CB(CstBB);
  AllocaInst *IdxA = CB.CreateAlloca(I32);
  AllocaInst *AccA = CB.CreateAlloca(I64);
  CB.CreateStore(ConstantInt::get(I32, 0), IdxA);
  CB.CreateStore(ConstantInt::get(I64, 0), AccA);
  CB.CreateBr(CLoop);

  IRBuilder<> CL(CLoop);
  Value *Idx = CL.CreateLoad(I32, IdxA);
  Value *Lim = CL.CreateZExt(CL.CreateLoad(I8, SzA), I32);
  CL.CreateCondBr(CL.CreateICmpULT(Idx, Lim), CBody, CDone);

  IRBuilder<> CBB(CBody);
  Value *Byte = getByte(CBB);
  Value *Acc = CBB.CreateLoad(I64, AccA);
  Value *Idx2 = CBB.CreateLoad(I32, IdxA);
  Value *ShAmt =
      CBB.CreateShl(CBB.CreateZExt(Idx2, I64), ConstantInt::get(I64, 3));
  CBB.CreateStore(
      CBB.CreateOr(Acc, CBB.CreateShl(CBB.CreateZExt(Byte, I64), ShAmt)), AccA);
  CBB.CreateStore(CBB.CreateAdd(Idx2, ConstantInt::get(I32, 1)), IdxA);
  CBB.CreateBr(CLoop);

  IRBuilder<> CD(CDone);
  CD.CreateRet(CD.CreateLoad(I64, AccA));
  return Fn;
}

// vmp_read_var_F(code*, ip*, size_out*, code_state*) -> data_off
static Function *buildReadVarFn(Module *M, Function *Host, Type *I8, Type *I32,
                                Type *I64, Type *I8Ptr, bool Encrypt) {
  Type *P = PointerType::get(M->getContext(), 0);
  FunctionType *FT =
      FunctionType::get(I64, {I8Ptr, P, P, P}, false);
  Function *Fn = Function::Create(FT, GlobalValue::InternalLinkage,
                                  Twine("vmp_read_var_") + Host->getName(), M);
  writeAnnotationMetadata(Fn, "novmp");
  auto A = Fn->arg_begin();
  Value *Code = &*A++;
  Value *IPArg = &*A++;
  Value *SizeOut = &*A++;
  Value *CodeStateArg = &*A++;
  BasicBlock *BB = BasicBlock::Create(M->getContext(), "entry", Fn);
  IRBuilder<> B(BB);
  auto getByte = [&]() -> Value * {
    Value *Cur = B.CreateLoad(I32, IPArg);
    Value *Ptr = B.CreateGEP(I8, Code, Cur);
    Value *Byte = B.CreateLoad(I8, Ptr);
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(I32, 1)), IPArg);
    if (Encrypt) {
      Value *X = B.CreateLoad(I32, CodeStateArg);
      Value *Is0 = B.CreateICmpEQ(X, ConstantInt::get(I32, 0));
      X = B.CreateSelect(Is0, ConstantInt::get(I32, 0xA5A5A5A5u), X);
      X = B.CreateXor(X, B.CreateShl(X, ConstantInt::get(I32, 13)));
      X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 17)));
      X = B.CreateXor(X, B.CreateShl(X, ConstantInt::get(I32, 5)));
      B.CreateStore(X, CodeStateArg);
      Byte = B.CreateXor(Byte, B.CreateTrunc(X, I8));
    }
    return Byte;
  };
  Value *Sz = getByte();
  (void)getByte(); // type_id
  B.CreateStore(Sz, SizeOut);
  Value *Off = ConstantInt::get(I64, 0);
  for (unsigned I = 0; I < 8; ++I) {
    Value *Byte = getByte();
    Off = B.CreateOr(Off, B.CreateShl(B.CreateZExt(Byte, I64),
                                      ConstantInt::get(I64, 8ull * I)));
  }
  B.CreateRet(Off);
  return Fn;
}

static Value *maskToSize(IRBuilder<> &B, Type *I8, Type *I64, Value *V,
                         Value *SizeI8) {
  Value *Bits = B.CreateShl(B.CreateZExt(SizeI8, I64), ConstantInt::get(I64, 3));
  Value *Full = B.CreateICmpUGE(SizeI8, ConstantInt::get(I8, 8));
  // avoid UB shift by 64
  Value *SafeBits =
      B.CreateSelect(Full, ConstantInt::get(I64, 0), Bits);
  Value *Mask = B.CreateSub(B.CreateShl(ConstantInt::get(I64, 1), SafeBits),
                            ConstantInt::get(I64, 1));
  return B.CreateSelect(Full, V, B.CreateAnd(V, Mask));
}

static bool buildInterpreter(Function *Host, VMPContext &V) {
  Module *M = Host->getParent();
  LLVMContext &Ctx = M->getContext();
  Type *I8 = Type::getInt8Ty(Ctx);
  Type *I32 = Type::getInt32Ty(Ctx);
  Type *I64 = Type::getInt64Ty(Ctx);
  Type *I8Ptr = PointerType::get(Ctx, 0);

  ArrayType *CodeTy = ArrayType::get(I8, std::max<size_t>(V.Code.size(), 1));
  auto *CodeGV = new GlobalVariable(
      *M, CodeTy, true, GlobalValue::InternalLinkage,
      ConstantDataArray::get(Ctx, V.Code), Twine("vmp_code_") + Host->getName());

  GlobalValue::LinkageTypes Link = Host->getLinkage();
  Host->deleteBody();
  Host->setLinkage(Link);
  turnOffOptimization(Host);

  auto *Entry = BasicBlock::Create(Ctx, "", Host);
  auto *Loop = BasicBlock::Create(Ctx, "", Host);
  auto *Disp = BasicBlock::Create(Ctx, "", Host);
  auto *Halt = BasicBlock::Create(Ctx, "", Host);
  auto *Trap = BasicBlock::Create(Ctx, "", Host);

  auto *HAlloca = BasicBlock::Create(Ctx, "", Host);
  auto *HLoad = BasicBlock::Create(Ctx, "", Host);
  auto *HStore = BasicBlock::Create(Ctx, "", Host);
  auto *HBin = BasicBlock::Create(Ctx, "", Host);
  auto *HIcmp = BasicBlock::Create(Ctx, "", Host);
  auto *HBr = BasicBlock::Create(Ctx, "", Host);
  auto *HRet = BasicBlock::Create(Ctx, "", Host);
  auto *HGep = BasicBlock::Create(Ctx, "", Host);
  auto *HCall = BasicBlock::Create(Ctx, "", Host);
  auto *HCast = BasicBlock::Create(Ctx, "", Host);
  auto *HSel = BasicBlock::Create(Ctx, "", Host);
  auto *HUnr = BasicBlock::Create(Ctx, "", Host);

  // call_handler(data*, func_id)
  FunctionType *CHTy = FunctionType::get(Type::getVoidTy(Ctx),
                                         {I8Ptr, I64}, false);
  Function *CallHandler = Function::Create(
      CHTy, GlobalValue::InternalLinkage,
      Twine("vmp_ch_") + Host->getName(), M);
  writeAnnotationMetadata(CallHandler, "novmp");
  {
    auto A = CallHandler->arg_begin();
    Value *DataArg = &*A++;
    DataArg->setName("data");
    Value *IdArg = &*A++;
    IdArg->setName("id");
    auto *CHEntry = BasicBlock::Create(Ctx, "", CallHandler);
    auto *CHDef = BasicBlock::Create(Ctx, "", CallHandler);
    IRBuilder<> CHB(CHEntry);
    SwitchInst *CSW = CHB.CreateSwitch(IdArg, CHDef,
                                       std::max<unsigned>(1, V.Calls.size()));
    IRBuilder<> CDef(CHDef);
    CDef.CreateRetVoid();

    for (const CallSiteInfo &CS : V.Calls) {
      auto *BB = BasicBlock::Create(Ctx, "", CallHandler);
      CSW->addCase(cast<ConstantInt>(ConstantInt::get(I64, CS.Id)), BB);
      IRBuilder<> CB(BB);
      SmallVector<Value *, 8> Args;
      for (const CallArgInfo &Arg : CS.Args) {
        Value *AV;
        if (Arg.IsConst) {
          if (Arg.Ty->isPointerTy())
            AV = CB.CreateIntToPtr(ConstantInt::get(I64, Arg.ConstVal), Arg.Ty);
          else
            AV = ConstantInt::get(Arg.Ty, Arg.ConstVal);
        } else {
          Value *Slot =
              CB.CreateGEP(I8, DataArg, ConstantInt::get(I64, Arg.Off));
          if (Arg.Ty->isPointerTy()) {
            Value *AsInt =
                CB.CreateLoad(I64, CB.CreateBitCast(Slot, I8Ptr));
            AV = CB.CreateIntToPtr(AsInt, Arg.Ty);
          } else {
            AV = CB.CreateLoad(Arg.Ty, CB.CreateBitCast(Slot, I8Ptr));
          }
        }
        Args.push_back(AV);
      }
      Value *RetV = nullptr;
      if (CS.DirectCallee) {
        RetV = CB.CreateCall(CS.FTy, CS.DirectCallee, Args);
      } else {
        Value *Slot =
            CB.CreateGEP(I8, DataArg, ConstantInt::get(I64, CS.CalleeOff));
        Value *FPI = CB.CreateLoad(I64, CB.CreateBitCast(Slot, I8Ptr));
        Value *FP = CB.CreateIntToPtr(FPI, PointerType::get(Ctx, 0));
        RetV = CB.CreateCall(CS.FTy, FP, Args);
      }
      if (CS.HasRet) {
        Value *Slot =
            CB.CreateGEP(I8, DataArg, ConstantInt::get(I64, CS.RetOff));
        if (CS.RetTy->isPointerTy()) {
          Value *AsInt = CB.CreatePtrToInt(RetV, I64);
          CB.CreateStore(AsInt, CB.CreateBitCast(Slot, I8Ptr));
        } else {
          CB.CreateStore(RetV, CB.CreateBitCast(Slot, I8Ptr));
        }
      }
      CB.CreateRetVoid();
    }
  }

  const bool Encrypt = V.Encrypt;
  Function *EvalFn = buildEvalFn(M, Host, I8, I32, I64, I8Ptr, Encrypt);
  Function *ReadVarFn = buildReadVarFn(M, Host, I8, I32, I64, I8Ptr, Encrypt);

  IRBuilder<> EB(Entry);
  uint32_t DS = std::max(V.DataSize, 8u);
  AllocaInst *DataAlloca =
      EB.CreateAlloca(ArrayType::get(I8, DS), nullptr, "vmp_data");
  Value *Data = EB.CreateBitCast(DataAlloca, I8Ptr);
  EB.CreateMemSet(Data, ConstantInt::get(I8, 0), DS, Align(1));

  for (Argument &Arg : Host->args()) {
    uint32_t Off = V.off(&Arg);
    Value *Slot = EB.CreateGEP(I8, Data, ConstantInt::get(I64, Off));
    if (Arg.getType()->isPointerTy()) {
      Value *AsInt = EB.CreatePtrToInt(&Arg, I64);
      EB.CreateStore(AsInt, EB.CreateBitCast(Slot, PointerType::get(Ctx, 0)));
    } else {
      EB.CreateStore(&Arg, EB.CreateBitCast(Slot, PointerType::get(Ctx, 0)));
    }
  }

  // Materialize compile-time addresses of referenced globals / functions.
  for (const GlobalSlot &GS : V.Globals) {
    Value *Slot = EB.CreateGEP(I8, Data, ConstantInt::get(I64, GS.Off));
    Value *AsInt = EB.CreatePtrToInt(GS.GV, I64);
    EB.CreateStore(AsInt, EB.CreateBitCast(Slot, PointerType::get(Ctx, 0)));
  }

  AllocaInst *IP = EB.CreateAlloca(I32, nullptr, "ip");
  EB.CreateStore(ConstantInt::get(I32, 0), IP);
  AllocaInst *Run = EB.CreateAlloca(I8, nullptr, "run");
  EB.CreateStore(ConstantInt::get(I8, 1), Run);
  AllocaInst *OpState = EB.CreateAlloca(I32, nullptr, "op_state");
  AllocaInst *CodeState = EB.CreateAlloca(I32, nullptr, "code_state");
  EB.CreateStore(ConstantInt::get(I32, 0), OpState);
  EB.CreateStore(ConstantInt::get(I32, 0), CodeState);
  Value *Code = EB.CreateBitCast(CodeGV, I8Ptr);

  // BB seed table: obfuscated as [N x {i32, i32, i32}] XORed with a per-function
  // key stream; SeedReloadFn decodes on load, so the plaintext seeds never sit
  // in a readable global.
  StructType *SeedTy = StructType::get(Ctx, {I32, I32, I32});
  unsigned NSeeds = std::max<size_t>(V.BBSeeds.size(), 1);
  ArrayType *SeedArrTy = ArrayType::get(SeedTy, NSeeds);
  // Mask stream derived from the host function name (independent of seeds).
  // mask(n) = (n+1)-th draw; runtime vmp_mask_<fn> replays identically.
  uint32_t SeedMask0 = fnHashSeed((Twine("seeds|") + Host->getName()).str());
  auto seedMaskAt = [&](unsigned Idx, unsigned Field) -> uint32_t {
    // field 0 = entry ip stays plaintext (the reload matches on it).
    if (Field == 0)
      return 0;
    return maskReplay(SeedMask0, Idx * 2u + (Field - 1));
  };
  SmallVector<Constant *, 8> SeedElts;
  for (unsigned SI = 0; SI < NSeeds; ++SI) {
    const BBSeedInfo &S = SI < V.BBSeeds.size()
                              ? V.BBSeeds[SI]
                              : BBSeedInfo{0, 0, 1, 1, {}};
    uint32_t OpM = seedMaskAt(SI, 1);
    uint32_t CdM = seedMaskAt(SI, 2);
    SeedElts.push_back(ConstantStruct::get(
        SeedTy, {ConstantInt::get(I32, S.EntryIP),
                 ConstantInt::get(I32, static_cast<uint32_t>(S.OpcodeSeed ^ OpM)),
                 ConstantInt::get(I32, static_cast<uint32_t>(S.CodeSeed ^ CdM))}));
  }
  auto *SeedGV = new GlobalVariable(
      *M, SeedArrTy, true, GlobalValue::InternalLinkage,
      ConstantArray::get(SeedArrTy, SeedElts),
      Twine("vmp_seeds_") + Host->getName());

  // Build seed reload as internal function for cleanliness
  // Runtime mask replay helper: vmp_mask_<fn>(n) = (n+1)-th draw of the
  // per-function mask stream.  Decodes vmp_seeds_ entries on load.
  FunctionType *MkTy = FunctionType::get(I32, {I32}, false);
  Function *MaskFn = Function::Create(
      MkTy, GlobalValue::InternalLinkage,
      Twine("vmp_mask_") + Host->getName(), M);
  writeAnnotationMetadata(MaskFn, "novmp");
  {
    BasicBlock *MB = BasicBlock::Create(Ctx, "", MaskFn);
    IRBuilder<> MBld(MB);
    // PRNG state, seeded with the same constant the emitter used.
    AllocaInst *StA = MBld.CreateAlloca(I32);
    MBld.CreateStore(ConstantInt::get(I32, SeedMask0), StA);
    AllocaInst *NA = MBld.CreateAlloca(I32);
    MBld.CreateStore(&*MaskFn->arg_begin(), NA);
    auto *MLoop = BasicBlock::Create(Ctx, "", MaskFn);
    auto *MBody = BasicBlock::Create(Ctx, "", MaskFn);
    auto *MDone = BasicBlock::Create(Ctx, "", MaskFn);
    MBld.CreateBr(MLoop);
    IRBuilder<> ML(MLoop);
    Value *N = ML.CreateLoad(I32, NA);
    ML.CreateCondBr(ML.CreateICmpSGT(N, ConstantInt::get(I32, 0)), MBody, MDone);
    IRBuilder<> MBd(MBody);
    MBd.CreateStore(MBd.CreateSub(MBd.CreateLoad(I32, NA),
                                  ConstantInt::get(I32, 1)),
                    NA);
    Value *X = MBd.CreateLoad(I32, StA);
    X = MBd.CreateSelect(MBd.CreateICmpEQ(X, ConstantInt::get(I32, 0)),
                         ConstantInt::get(I32, 0xA5A5A5A5u), X);
    X = MBd.CreateXor(X, MBd.CreateShl(X, ConstantInt::get(I32, 13)));
    X = MBd.CreateXor(X, MBd.CreateLShr(X, ConstantInt::get(I32, 17)));
    X = MBd.CreateXor(X, MBd.CreateShl(X, ConstantInt::get(I32, 5)));
    MBd.CreateStore(X, StA);
    MBd.CreateBr(MLoop);
    IRBuilder<> MD(MDone);
    // The loop above drew n times; mask(n) needs n+1 draws total.
    {
      Value *X = MD.CreateLoad(I32, StA);
      X = MD.CreateSelect(MD.CreateICmpEQ(X, ConstantInt::get(I32, 0)),
                          ConstantInt::get(I32, 0xA5A5A5A5u), X);
      X = MD.CreateXor(X, MD.CreateShl(X, ConstantInt::get(I32, 13)));
      X = MD.CreateXor(X, MD.CreateLShr(X, ConstantInt::get(I32, 17)));
      X = MD.CreateXor(X, MD.CreateShl(X, ConstantInt::get(I32, 5)));
      MD.CreateStore(X, StA);
    }
    MD.CreateRet(MD.CreateLoad(I32, StA));
  }

  FunctionType *SRTy =
      FunctionType::get(Type::getVoidTy(Ctx),
                        {I32, PointerType::get(Ctx, 0), PointerType::get(Ctx, 0)},
                        false);
  Function *SeedReloadFn = Function::Create(
      SRTy, GlobalValue::InternalLinkage,
      Twine("vmp_seed_") + Host->getName(), M);
  writeAnnotationMetadata(SeedReloadFn, "novmp");
  {
    auto SA = SeedReloadFn->arg_begin();
    Value *Want = &*SA++;
    Value *OpOut = &*SA++;
    Value *CdOut = &*SA++;
    auto *SEntry = BasicBlock::Create(Ctx, "", SeedReloadFn);
    IRBuilder<> SB(SEntry);
    if (!Encrypt) {
      SB.CreateStore(ConstantInt::get(I32, 0), OpOut);
      SB.CreateStore(ConstantInt::get(I32, 0), CdOut);
      SB.CreateRetVoid();
    } else {
      auto *SLoop = BasicBlock::Create(Ctx, "", SeedReloadFn);
      auto *SBody = BasicBlock::Create(Ctx, "", SeedReloadFn);
      auto *SMatch = BasicBlock::Create(Ctx, "", SeedReloadFn);
      auto *SNext = BasicBlock::Create(Ctx, "", SeedReloadFn);
      auto *SDone = BasicBlock::Create(Ctx, "", SeedReloadFn);
      // Same mask stream as the emitter, replayed at runtime to recover the
      // plaintext seeds: mask for (idx, field) = draw idx*2+field-1.
      uint32_t SeedMaskS = fnHashSeed((Twine("seeds|") + Host->getName()).str());
      AllocaInst *IdxA = SB.CreateAlloca(I32);
      SB.CreateStore(ConstantInt::get(I32, 0), IdxA);
      SB.CreateBr(SLoop);
      IRBuilder<> SL(SLoop);
      Value *Idx = SL.CreateLoad(I32, IdxA);
      SL.CreateCondBr(
          SL.CreateICmpULT(Idx, ConstantInt::get(I32, NSeeds)), SBody, SDone);
      IRBuilder<> SBd(SBody);
      Value *Zero = ConstantInt::get(I32, 0);
      Value *GEP = SBd.CreateInBoundsGEP(SeedArrTy, SeedGV, {Zero, Idx});
      Value *EntP = SBd.CreateStructGEP(SeedTy, GEP, 0);
      Value *Ent = SBd.CreateLoad(I32, EntP);
      SBd.CreateCondBr(SBd.CreateICmpEQ(Ent, Want), SMatch, SNext);
      IRBuilder<> SM(SMatch);
      Value *OpP = SM.CreateStructGEP(SeedTy, GEP, 1);
      Value *CdP = SM.CreateStructGEP(SeedTy, GEP, 2);
      // Replay the mask stream at runtime: vmp_mask_<fn>(idx*2) returns the
      // (idx,1) mask and its +1 continuation gives (idx,2).  Both XORed in.
      Value *MIdx = SM.CreateZExt(Idx, I32);
      Value *Draw1 = SM.CreateMul(MIdx, ConstantInt::get(I32, 2));
      Value *OpMask = SM.CreateCall(MaskFn, {Draw1});
      Value *CdMask =
          SM.CreateCall(MaskFn, {SM.CreateAdd(Draw1, ConstantInt::get(I32, 1))});
      SM.CreateStore(SM.CreateXor(SM.CreateLoad(I32, OpP), OpMask), OpOut);
      SM.CreateStore(SM.CreateXor(SM.CreateLoad(I32, CdP), CdMask), CdOut);
      SM.CreateRetVoid();
      IRBuilder<> SN(SNext);
      SN.CreateStore(SN.CreateAdd(Idx, ConstantInt::get(I32, 1)), IdxA);
      SN.CreateBr(SLoop);
      IRBuilder<> SD(SDone);
      Value *GEP0 = SD.CreateInBoundsGEP(
          SeedArrTy, SeedGV,
          {ConstantInt::get(I32, 0), ConstantInt::get(I32, 0)});
      SD.CreateStore(SD.CreateLoad(I32, SD.CreateStructGEP(SeedTy, GEP0, 1)),
                     OpOut);
      SD.CreateStore(SD.CreateLoad(I32, SD.CreateStructGEP(SeedTy, GEP0, 2)),
                     CdOut);
      SD.CreateRetVoid();
    }
  }

  EB.CreateCall(SeedReloadFn, {ConstantInt::get(I32, 0), OpState, CodeState});
  EB.CreateBr(Loop);

  IRBuilder<> LB(Loop);
  LB.CreateCondBr(
      LB.CreateICmpNE(LB.CreateLoad(I8, Run), ConstantInt::get(I8, 0)), Disp,
      Halt);

  IRBuilder<> DB(Disp);
  AllocaInst *CSForFetch = Encrypt ? CodeState : nullptr;
  AllocaInst *OSForFetch = Encrypt ? OpState : nullptr;
  Value *Op = irFetchOp(DB, I8, I32, Code, IP, CSForFetch, OSForFetch);
  auto ci8 = [&](uint64_t V) {
    return cast<ConstantInt>(ConstantInt::get(I8, V));
  };
  // IP bound check: any way the bytecode or a bug drives ip past the code
  // image must land in Trap instead of reading out of bounds (SIGSEGV on
  // Android).  CodeSize is a compile-time constant of this function's image.
  auto *IPChk = BasicBlock::Create(Ctx, "", Host);
  IRBuilder<> XB(IPChk);
  Value *IPLim = XB.CreateLoad(I32, IP);
  XB.CreateStore(
      XB.CreateZExt(XB.CreateICmpULT(IPLim, ConstantInt::get(I32, static_cast<uint32_t>(V.Code.size()))), I8),
      Run);
  XB.CreateBr(Loop);
  LB.CreateCondBr(
      LB.CreateICmpNE(LB.CreateLoad(I8, Run), ConstantInt::get(I8, 0)), IPChk,
      Halt);
  SwitchInst *SW = XB.CreateSwitch(Op, Trap, 16);
  SW->addCase(ci8(V.op(OP_ALLOCA)), HAlloca);
  SW->addCase(ci8(V.op(OP_LOAD)), HLoad);
  SW->addCase(ci8(V.op(OP_STORE)), HStore);
  SW->addCase(ci8(V.op(OP_BINOP)), HBin);
  SW->addCase(ci8(V.op(OP_ICMP)), HIcmp);
  SW->addCase(ci8(V.op(OP_BR)), HBr);
  SW->addCase(ci8(V.op(OP_RET)), HRet);
  SW->addCase(ci8(V.op(OP_GEP)), HGep);
  SW->addCase(ci8(V.op(OP_CALL)), HCall);
  SW->addCase(ci8(V.op(OP_CAST)), HCast);
  SW->addCase(ci8(V.op(OP_SELECT)), HSel);
  SW->addCase(ci8(V.op(OP_UNREACHABLE)), HUnr);

  auto callEval = [&](IRBuilder<> &B, Value *SizeOut = nullptr) -> Value * {
    if (!SizeOut) {
      AllocaInst *Tmp = B.CreateAlloca(I8);
      SizeOut = Tmp;
    }
    return B.CreateCall(EvalFn, {Code, IP, Data, SizeOut, CodeState});
  };
  auto callReadVar = [&](IRBuilder<> &B, AllocaInst *SzOut) {
    return B.CreateCall(ReadVarFn, {Code, IP, SzOut, CodeState});
  };
  auto getB = [&](IRBuilder<> &B) {
    return irGetByte(B, I8, I32, Code, IP, Encrypt ? CodeState : nullptr);
  };
  auto getU = [&](IRBuilder<> &B) {
    return irGetU64(B, I8, I32, I64, Code, IP, Encrypt ? CodeState : nullptr);
  };

  // ALLOCA
  {
    IRBuilder<> B(HAlloca);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *AreaOff = getU(B);
    Value *VA = B.CreatePtrToInt(B.CreateGEP(I8, Data, AreaOff), I64);
    irStoreBytes(B, I8, I64, Data, ResOff, VA, ConstantInt::get(I8, kPointerSize));
    B.CreateBr(Loop);
  }

  // LOAD
  {
    IRBuilder<> B(HLoad);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *Sz = B.CreateLoad(I8, SzT);
    Value *Addr = callEval(B);
    Value *Val = irLoadMem(B, I8, I64, I8Ptr, Addr, Sz);
    irStoreBytes(B, I8, I64, Data, ResOff, Val, Sz);
    B.CreateBr(Loop);
  }

  // STORE
  {
    IRBuilder<> B(HStore);
    // manually read packed val then eval ptr
    auto *SVar = BasicBlock::Create(Ctx, "", Host);
    auto *SCst = BasicBlock::Create(Ctx, "", Host);
    auto *SCLoop = BasicBlock::Create(Ctx, "", Host);
    auto *SCBody = BasicBlock::Create(Ctx, "", Host);
    auto *SCDone = BasicBlock::Create(Ctx, "", Host);
    auto *SJoin = BasicBlock::Create(Ctx, "", Host);

    Value *Size = getB(B);
    Value *Tid = getB(B);
    AllocaInst *SzA = B.CreateAlloca(I8);
    AllocaInst *ValA = B.CreateAlloca(I64);
    B.CreateStore(Size, SzA);
    B.CreateCondBr(B.CreateICmpEQ(Tid, ConstantInt::get(I8, 0)), SVar, SCst);

    IRBuilder<> SV(SVar);
    Value *Off = getU(SV);
    SV.CreateStore(
        irLoadBytes(SV, I8, I64, Data, Off, SV.CreateLoad(I8, SzA)), ValA);
    SV.CreateBr(SJoin);

    IRBuilder<> SC(SCst);
    AllocaInst *IdxA = SC.CreateAlloca(I32);
    AllocaInst *AccA = SC.CreateAlloca(I64);
    SC.CreateStore(ConstantInt::get(I32, 0), IdxA);
    SC.CreateStore(ConstantInt::get(I64, 0), AccA);
    SC.CreateBr(SCLoop);

    IRBuilder<> SCL(SCLoop);
    Value *Idx = SCL.CreateLoad(I32, IdxA);
    Value *Lim = SCL.CreateZExt(SCL.CreateLoad(I8, SzA), I32);
    SCL.CreateCondBr(SCL.CreateICmpULT(Idx, Lim), SCBody, SCDone);

    IRBuilder<> SCB(SCBody);
    Value *Byte = getB(SCB);
    Value *Idx2 = SCB.CreateLoad(I32, IdxA);
    Value *Acc = SCB.CreateLoad(I64, AccA);
    Value *Sh =
        SCB.CreateShl(SCB.CreateZExt(Idx2, I64), ConstantInt::get(I64, 3));
    SCB.CreateStore(
        SCB.CreateOr(Acc, SCB.CreateShl(SCB.CreateZExt(Byte, I64), Sh)), AccA);
    SCB.CreateStore(SCB.CreateAdd(Idx2, ConstantInt::get(I32, 1)), IdxA);
    SCB.CreateBr(SCLoop);

    IRBuilder<> SCD(SCDone);
    SCD.CreateStore(SCD.CreateLoad(I64, AccA), ValA);
    SCD.CreateBr(SJoin);

    IRBuilder<> SJ(SJoin);
    Value *Addr = callEval(SJ);
    irStoreMem(SJ, I8, I64, I8Ptr, Addr, SJ.CreateLoad(I64, ValA),
               SJ.CreateLoad(I8, SzA));
    SJ.CreateBr(Loop);
  }

  // BINOP
  {
    IRBuilder<> B(HBin);
    Value *Sub = getB(B);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *Sz = B.CreateLoad(I8, SzT);
    // Operands exist in two shapes and the opcode decides which one is right.
    //  * unsigned ops (udiv/urem/lshr) and every shift *count* must be
    //    zero-extended: sign-extending them feeds the operand's high bit into
    //    the result (`udiv i32 0x80000000, 4` used to be computed as
    //    `udiv i64 0xFFFFFFFF80000000, 4`) and a negative shift count is UB.
    //  * signed ops (sdiv/srem/ashr) need the sign-extended form.
    //  * add/sub/mul/shl/and/or/xor agree on the low Sz bytes either way, so
    //    the zero-extended pair keeps them well defined.
    AllocaInst *LSz = B.CreateAlloca(I8);
    AllocaInst *RSz = B.CreateAlloca(I8);
    Value *LHSU = maskToSize(B, I8, I64, callEval(B, LSz), Sz);
    Value *RHSU = maskToSize(B, I8, I64, callEval(B, RSz), Sz);
    Value *LHSS = sextToI64(B, I8, I64, LHSU, Sz);
    Value *RHSS = sextToI64(B, I8, I64, RHSU, Sz);

    auto *Def = BasicBlock::Create(Ctx, "", Host);
    auto *Join = BasicBlock::Create(Ctx, "", Host);
    AllocaInst *RA = B.CreateAlloca(I64);
    SwitchInst *BS = B.CreateSwitch(Sub, Def, 13);

    auto add = [&](uint8_t CodeV, auto Fn, Value *L, Value *R) {
      auto *BB = BasicBlock::Create(Ctx, "", Host);
      BS->addCase(cast<ConstantInt>(ConstantInt::get(I8, CodeV)), BB);
      IRBuilder<> CB(BB);
      CB.CreateStore(Fn(CB, L, R), RA);
      CB.CreateBr(Join);
    };
    add(BIN_ADD, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateAdd(L, R); }, LHSU, RHSU);
    add(BIN_SUB, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateSub(L, R); }, LHSU, RHSU);
    add(BIN_MUL, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateMul(L, R); }, LHSU, RHSU);
    add(BIN_UDIV, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateUDiv(L, R); }, LHSU, RHSU);
    add(BIN_SDIV, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateSDiv(L, R); }, LHSS, RHSS);
    add(BIN_UREM, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateURem(L, R); }, LHSU, RHSU);
    add(BIN_SREM, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateSRem(L, R); }, LHSS, RHSS);
    add(BIN_SHL, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateShl(L, R); }, LHSU, RHSU);
    add(BIN_LSHR, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateLShr(L, R); }, LHSU, RHSU);
    add(BIN_ASHR, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateAShr(L, R); }, LHSS, RHSS);
    add(BIN_AND, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateAnd(L, R); }, LHSU, RHSU);
    add(BIN_OR, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateOr(L, R); }, LHSU, RHSU);
    add(BIN_XOR, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateXor(L, R); }, LHSU, RHSU);

    IRBuilder<> BD(Def);
    BD.CreateStore(ConstantInt::get(I64, 0), RA);
    BD.CreateBr(Join);

    IRBuilder<> BJ(Join);
    Value *Res = maskToSize(BJ, I8, I64, BJ.CreateLoad(I64, RA), Sz);
    irStoreBytes(BJ, I8, I64, Data, ResOff, Res, Sz);
    BJ.CreateBr(Loop);
  }

  // ICMP
  {
    IRBuilder<> B(HIcmp);
    Value *Pred = getB(B);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    AllocaInst *LSz = B.CreateAlloca(I8);
    AllocaInst *RSz = B.CreateAlloca(I8);
    Value *LHS0 = callEval(B, LSz);
    Value *RHS0 = callEval(B, RSz);
    Value *LSzV = B.CreateLoad(I8, LSz);
    Value *RSzV = B.CreateLoad(I8, RSz);
    // Unsigned compares: zero-extend (mask). Signed: sign-extend.
    Value *LHSZ = maskToSize(B, I8, I64, LHS0, LSzV);
    Value *RHSZ = maskToSize(B, I8, I64, RHS0, RSzV);
    Value *LHSS = sextToI64(B, I8, I64, LHSZ, LSzV);
    Value *RHSS = sextToI64(B, I8, I64, RHSZ, RSzV);
    auto *Def = BasicBlock::Create(Ctx, "", Host);
    auto *Join = BasicBlock::Create(Ctx, "", Host);
    AllocaInst *RA = B.CreateAlloca(I8);
    SwitchInst *IS = B.CreateSwitch(Pred, Def, 10);
    auto addU = [&](uint8_t C, auto Fn) {
      auto *BB = BasicBlock::Create(Ctx, "", Host);
      IS->addCase(cast<ConstantInt>(ConstantInt::get(I8, C)), BB);
      IRBuilder<> CB(BB);
      CB.CreateStore(CB.CreateZExt(Fn(CB, LHSZ, RHSZ), I8), RA);
      CB.CreateBr(Join);
    };
    auto addS = [&](uint8_t C, auto Fn) {
      auto *BB = BasicBlock::Create(Ctx, "", Host);
      IS->addCase(cast<ConstantInt>(ConstantInt::get(I8, C)), BB);
      IRBuilder<> CB(BB);
      CB.CreateStore(CB.CreateZExt(Fn(CB, LHSS, RHSS), I8), RA);
      CB.CreateBr(Join);
    };
    addU(ICMP_EQ, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpEQ(L, R); });
    addU(ICMP_NE, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpNE(L, R); });
    addU(ICMP_UGT, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpUGT(L, R); });
    addU(ICMP_UGE, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpUGE(L, R); });
    addU(ICMP_ULT, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpULT(L, R); });
    addU(ICMP_ULE, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpULE(L, R); });
    addS(ICMP_SGT, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpSGT(L, R); });
    addS(ICMP_SGE, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpSGE(L, R); });
    addS(ICMP_SLT, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpSLT(L, R); });
    addS(ICMP_SLE, [](IRBuilder<> &B, Value *L, Value *R) { return B.CreateICmpSLE(L, R); });
    IRBuilder<> ID(Def);
    ID.CreateStore(ConstantInt::get(I8, 0), RA);
    ID.CreateBr(Join);
    IRBuilder<> IJ(Join);
    irStoreBytes(IJ, I8, I64, Data, ResOff,
                 IJ.CreateZExt(IJ.CreateLoad(I8, RA), I64),
                 ConstantInt::get(I8, 1));
    IJ.CreateBr(Loop);
  }

  // BR
  {
    IRBuilder<> B(HBr);
    Value *Kind = getB(B);
    auto *U = BasicBlock::Create(Ctx, "", Host);
    auto *C = BasicBlock::Create(Ctx, "", Host);
    B.CreateCondBr(B.CreateICmpEQ(Kind, ConstantInt::get(I8, 0)), U, C);
    IRBuilder<> BU(U);
    Value *TU = BU.CreateTrunc(getU(BU), I32);
    BU.CreateStore(TU, IP);
    BU.CreateCall(SeedReloadFn, {TU, OpState, CodeState});
    BU.CreateBr(Loop);
    IRBuilder<> BC(C);
    Value *Cond = callEval(BC);
    Value *TT = getU(BC);
    Value *TF = getU(BC);
    Value *T = BC.CreateSelect(
        BC.CreateICmpNE(Cond, ConstantInt::get(I64, 0)), TT, TF);
    Value *TI = BC.CreateTrunc(T, I32);
    BC.CreateStore(TI, IP);
    BC.CreateCall(SeedReloadFn, {TI, OpState, CodeState});
    BC.CreateBr(Loop);
  }

  // RET
  {
    IRBuilder<> B(HRet);
    Value *Has = getB(B);
    auto *RV = BasicBlock::Create(Ctx, "", Host);
    auto *RN = BasicBlock::Create(Ctx, "", Host);
    B.CreateCondBr(B.CreateICmpNE(Has, ConstantInt::get(I8, 0)), RV, RN);
    IRBuilder<> RVB(RV);
    Value *Val = callEval(RVB);
    uint32_t RSz = Host->getReturnType()->isVoidTy()
                       ? 0u
                       : V.typeSize(Host->getReturnType());
    if (RSz == 0)
      RSz = 8;
    irStoreBytes(RVB, I8, I64, Data, ConstantInt::get(I64, 0), Val,
                 ConstantInt::get(I8, RSz));
    RVB.CreateStore(ConstantInt::get(I8, 0), Run);
    RVB.CreateBr(Loop);
    IRBuilder<> RNB(RN);
    RNB.CreateStore(ConstantInt::get(I8, 0), Run);
    RNB.CreateBr(Loop);
  }

  // GEP: kind, elem_size, res, base, index
  {
    IRBuilder<> B(HGep);
    Value *Kind = getB(B);
    Value *ElemSz = getU(B);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *Base = callEval(B);
    AllocaInst *DispSz = B.CreateAlloca(I8);
    Value *DispRaw = callEval(B, DispSz);
    // GEP indices are signed, and the field is a raw byte offset for kind 0, so
    // the displacement is sign-extended from its own width.  Reading it
    // zero-extended turned a dynamic `p[-1]` into `p[0xFFFFFFFF]`.
    Value *Disp =
        sextToI64(B, I8, I64, DispRaw, B.CreateLoad(I8, DispSz));
    // kind==0: base+disp; kind==1: base+disp*elem
    Value *Scaled = B.CreateMul(Disp, ElemSz);
    Value *Off = B.CreateSelect(
        B.CreateICmpEQ(Kind, ConstantInt::get(I8, 0)), Disp, Scaled);
    Value *Res = B.CreateAdd(Base, Off);
    irStoreBytes(B, I8, I64, Data, ResOff, Res,
                 ConstantInt::get(I8, kPointerSize));
    B.CreateBr(Loop);
  }

  // CALL: func_id → call_handler(data, id)
  {
    IRBuilder<> B(HCall);
    Value *Fid = getU(B);
    B.CreateCall(CallHandler, {Data, Fid});
    B.CreateBr(Loop);
  }

  // CAST
  {
    IRBuilder<> B(HCast);
    Value *Kind = getB(B);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *DstSz = B.CreateLoad(I8, SzT);
    AllocaInst *SrcSzT = B.CreateAlloca(I8);
    Value *Src = callEval(B, SrcSzT);
    Value *SrcSz = B.CreateLoad(I8, SrcSzT);
    auto *SextBB = BasicBlock::Create(Ctx, "", Host);
    auto *NormBB = BasicBlock::Create(Ctx, "", Host);
    auto *Join = BasicBlock::Create(Ctx, "", Host);
    AllocaInst *RA = B.CreateAlloca(I64);
    B.CreateCondBr(B.CreateICmpEQ(Kind, ConstantInt::get(I8, CAST_SEXT)), SextBB,
                   NormBB);
    IRBuilder<> CS(SextBB);
    // Sign extension works from the *source* width: in `sext i32 -> i64` the
    // sign bit is at 31, not 63.  Keying it off the destination width left
    // `(int64_t)(int32_t)-1` as 0x00000000FFFFFFFF, which then became a wild
    // pointer in the very common `p[i - 1]` shape.
    CS.CreateStore(sextToI64(CS, I8, I64, Src, SrcSz), RA);
    CS.CreateBr(Join);
    // trunc / zext / bitcast / ptrtoint / inttoptr all keep the low DstSz bytes
    // of the source and zero the rest; the store below drops the excess.
    IRBuilder<> CN(NormBB);
    CN.CreateStore(maskToSize(CN, I8, I64, Src, DstSz), RA);
    CN.CreateBr(Join);
    IRBuilder<> CJ(Join);
    irStoreBytes(CJ, I8, I64, Data, ResOff, CJ.CreateLoad(I64, RA), DstSz);
    CJ.CreateBr(Loop);
  }

  // SELECT
  {
    IRBuilder<> B(HSel);
    AllocaInst *SzT = B.CreateAlloca(I8);
    Value *ResOff = callReadVar(B, SzT);
    Value *Sz = B.CreateLoad(I8, SzT);
    Value *Cond = callEval(B);
    Value *TV = callEval(B);
    Value *FV = callEval(B);
    Value *R = B.CreateSelect(
        B.CreateICmpNE(Cond, ConstantInt::get(I64, 0)), TV, FV);
    irStoreBytes(B, I8, I64, Data, ResOff, R, Sz);
    B.CreateBr(Loop);
  }

  {
    IRBuilder<> B(HUnr);
    B.CreateStore(ConstantInt::get(I8, 0), Run);
    B.CreateBr(Loop);
  }
  {
    IRBuilder<> B(Trap);
    B.CreateStore(ConstantInt::get(I8, 0), Run);
    B.CreateBr(Loop);
  }

  {
    IRBuilder<> B(Halt);
    Type *RetTy = Host->getReturnType();
    if (RetTy->isVoidTy()) {
      B.CreateRetVoid();
    } else if (RetTy->isPointerTy()) {
      Value *V = irLoadBytes(B, I8, I64, Data, ConstantInt::get(I64, 0),
                             ConstantInt::get(I8, kPointerSize));
      B.CreateRet(B.CreateIntToPtr(V, RetTy));
    } else {
      uint32_t Sz = V.typeSize(RetTy);
      Value *V = irLoadBytes(B, I8, I64, Data, ConstantInt::get(I64, 0),
                             ConstantInt::get(I8, Sz));
      B.CreateRet(B.CreateTrunc(V, RetTy));
    }
  }

  if (verifyFunction(*Host, &errs()) || verifyFunction(*EvalFn, &errs()) ||
      verifyFunction(*ReadVarFn, &errs()) ||
      verifyFunction(*CallHandler, &errs()) ||
      verifyFunction(*SeedReloadFn, &errs())) {
    errs() << "[VMP] verify failed for " << Host->getName() << "\n";
    return false;
  }
  return true;
}

static bool canVirtualize(Function &F, std::string &Why) {
  if (F.isDeclaration()) {
    Why = "declaration";
    return false;
  }
  if (F.isVarArg()) {
    Why = "vararg (unsupported; annotate novmp or refactor)";
    return false;
  }
  for (BasicBlock &BB : F) {
    if (BB.isEHPad() || BB.isLandingPad()) {
      Why = "exception handling unsupported";
      return false;
    }
    for (Instruction &I : BB) {
      if (isa<InvokeInst>(&I) || isa<ResumeInst>(&I) ||
          isa<CatchSwitchInst>(&I) || isa<LandingPadInst>(&I)) {
        Why = "eh instruction unsupported";
        return false;
      }
      if (I.getType()->isFloatingPointTy() ||
          (I.getNumOperands() > 0 && I.getOperand(0)->getType()->isFloatingPointTy())) {
        // Allow pure integer functions; reject when float values appear.
        if (isa<FPMathOperator>(&I) || isa<FCmpInst>(&I) ||
            I.getOpcode() == Instruction::FPToUI ||
            I.getOpcode() == Instruction::FPToSI ||
            I.getOpcode() == Instruction::UIToFP ||
            I.getOpcode() == Instruction::SIToFP ||
            I.getOpcode() == Instruction::FPTrunc ||
            I.getOpcode() == Instruction::FPExt) {
          Why = "floating-point IR unsupported (hard-fail skip)";
          return false;
        }
      }
    }
  }
  return true;
}

static bool virtualizeFunction(Function &F) {
  // Never virtualize our own interpreter helpers.
  StringRef N = F.getName();
  if (N.starts_with("vmp_eval_") || N.starts_with("vmp_read_var_") ||
      N.starts_with("vmp_code_") || N.starts_with("vmp_ch_") ||
      N.ends_with(".vmp_bak")) {
    return false;
  }
  std::string Why;
  if (!canVirtualize(F, Why)) {
    errs() << "[VMP] skip " << F.getName() << " (" << Why << ")\n";
    return false;
  }

  FixFunctionConstantExpr(&F);
  fixStack(&F);
  FixFunctionConstantExpr(&F);

  // Backup after preprocess in case interpreter build fails.
  ValueToValueMapTy VMap;
  Function *Backup = CloneFunction(&F, VMap);
  Backup->setName(Twine(F.getName()) + ".vmp_bak");
  Backup->setLinkage(GlobalValue::InternalLinkage);

  VMPContext C;
  C.F = &F;
  C.M = F.getParent();
  C.DL = &F.getParent()->getDataLayout();
  C.Encrypt = VmpEncrypt;
  C.initOpcodeMap(F.getName());
  // Annotation override: novmpenc / vmpenc
  bool EncOpt = C.Encrypt;
  if (toObfuscateBoolOption(&F, "vmpenc", &EncOpt))
    C.Encrypt = EncOpt;

  if (!translateFunction(C)) {
    errs() << "[VMP] translate fail " << F.getName() << ": " << C.FailReason
           << "\n";
    Backup->eraseFromParent();
    return false;
  }

  errs() << "[VMP] " << F.getName() << " code=" << C.Code.size()
         << "B data=" << C.DataSize << "B encrypt=" << (C.Encrypt ? 1 : 0)
         << "\n";

  if (!buildInterpreter(&F, C)) {
    errs() << "[VMP] build fail, restore " << F.getName() << "\n";
    F.deleteBody();
    ValueToValueMapTy V2;
    auto AI = F.arg_begin();
    for (Argument &A : Backup->args()) {
      AI->setName(A.getName());
      V2[&A] = &*AI++;
    }
    SmallVector<ReturnInst *, 4> Rets;
    CloneFunctionInto(&F, Backup, V2, CloneFunctionChangeType::LocalChangesOnly,
                      Rets);
    Backup->eraseFromParent();
    return false;
  }

  Backup->eraseFromParent();
  return true;
}

static void postFlattenVmp(Function &F) {
  Module *M = F.getParent();
  auto hardenOne = [&](Function *HF) {
    if (!HF || HF->isDeclaration() || HF->empty())
      return;
    errs() << "[VMP] post-CFF on " << HF->getName() << "\n";
    FunctionPass *Fla = createFlatteningPass(true);
    Fla->runOnFunction(*HF);
    delete Fla;
  };
  // Host interpreter loop first, then helpers (eval/read/call/seed).
  hardenOne(&F);
  hardenOne(M->getFunction((Twine("vmp_eval_") + F.getName()).str()));
  hardenOne(M->getFunction((Twine("vmp_read_var_") + F.getName()).str()));
  hardenOne(M->getFunction((Twine("vmp_ch_") + F.getName()).str()));
  hardenOne(M->getFunction((Twine("vmp_seed_") + F.getName()).str()));
}

struct Virtualization : public FunctionPass {
  static char ID;
  bool flag;
  bool postFlatten;
  Virtualization() : FunctionPass(ID), flag(true), postFlatten(false) {}
  Virtualization(bool f, bool postFla = false)
      : FunctionPass(ID), flag(f), postFlatten(postFla) {}
  StringRef getPassName() const override { return "HikariVirtualization"; }
  bool runOnFunction(Function &F) override {
    loadVmpEnv();
    if (!toObfuscate(flag, &F, "vmp"))
      return false;
    errs() << "Running Virtualization On " << F.getName() << "\n";
    bool Changed = virtualizeFunction(F);
    // Combine with flattening: CFF after VMP (not before), so bytecode stays
    // compact while the interpreter control-flow is shredded.
    bool wantPost =
        postFlatten || VmpHarden || toObfuscate(false, &F, "vmpharden");
    if (Changed && wantPost)
      postFlattenVmp(F);
    // If VMP was skipped/failed but this function was reserved for post-CFF
    // (pre-CFF skipped), still apply CFF to the original body.
    if (!Changed && wantPost && !F.empty()) {
      errs() << "[VMP] fallback pre-style CFF on non-virtualized "
             << F.getName() << "\n";
      FunctionPass *Fla = createFlatteningPass(true);
      Fla->runOnFunction(F);
      delete Fla;
      return true;
    }
    return Changed;
  }
};

} // namespace

char Virtualization::ID = 0;
FunctionPass *llvm::createVirtualizationPass(bool flag, bool postFlatten) {
  return new Virtualization(flag, postFlatten);
}
INITIALIZE_PASS(Virtualization, "vmpobf", "Enable IR Virtualization (VMP).",
                false, false)
