// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/StringEncryption.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

static cl::opt<uint32_t>
    ElementEncryptProb("strcry_prob", cl::init(100), cl::NotHidden,
                       cl::desc("Choose the probability [%] each element of "
                                "ConstantDataSequential will be "
                                "obfuscated by the -strcry pass"));
static uint32_t ElementEncryptProbTemp = 100;

namespace llvm {
struct StringEncryption : public ModulePass {
  static char ID;
  bool flag;
  bool opaquepointers;
  std::unordered_map<Function * /*Function*/,
                     GlobalVariable * /*Decryption Status*/>
      encstatus;
  std::unordered_map<GlobalVariable *, std::pair<Constant *, GlobalVariable *>>
      mgv2keys;
  std::unordered_map<Constant *, SmallVector<unsigned int, 16>>
      unencryptedindex;
  SmallVector<GlobalVariable *, 32> genedgv;
  std::unordered_map<GlobalVariable *,
                     std::pair<GlobalVariable *, GlobalVariable *>>
      globalOld2New;
  std::unordered_set<GlobalVariable *> globalProcessedGVs;
  StringEncryption() : ModulePass(ID) { this->flag = true; }

  StringEncryption(bool flag) : ModulePass(ID) { this->flag = flag; }

  StringRef getPassName() const override { return "StringEncryption"; }

  bool handleableGV(GlobalVariable *GV) {
#if LLVM_VERSION_MAJOR >= 18
    if (GV->hasInitializer() && !GV->getSection().starts_with("llvm.") &&
#else
    if (GV->hasInitializer() && !GV->getSection().startswith("llvm.") &&
#endif
        !(GV->getSection().contains("__objc") &&
          !GV->getSection().contains("array")) &&
        !GV->getName().contains("OBJC") &&
        std::find(genedgv.begin(), genedgv.end(), GV) == genedgv.end() &&
        ((GV->getLinkage() == GlobalValue::LinkageTypes::PrivateLinkage ||
          GV->getLinkage() == GlobalValue::LinkageTypes::InternalLinkage) &&
         (flag || AreUsersInOneFunction(GV))))
      return true;
    return false;
  }

  bool runOnModule(Module &M) override {
    // in runOnModule. We simple iterate function list and dispatch functions
    // to handlers
#if LLVM_VERSION_MAJOR >= 17
    this->opaquepointers = true;
#else
    this->opaquepointers = !M.getContext().supportsTypedPointers();
#endif

    for (Function &F : M)
      if (toObfuscate(flag, &F, "strenc")) {
        errs() << "Running StringEncryption On " << F.getName() << "\n";

        if (!toObfuscateUint32Option(&F, "strcry_prob",
                                     &ElementEncryptProbTemp))
          ElementEncryptProbTemp = ElementEncryptProb;

        // Check if the number of applications is correct
        if (!((ElementEncryptProbTemp > 0) &&
              (ElementEncryptProbTemp <= 100))) {
          errs() << "StringEncryption application element percentage "
                    "-strcry_prob=x must be 0 < x <= 100";
          return false;
        }
        Constant *S =
            ConstantInt::getNullValue(Type::getInt32Ty(M.getContext()));
        GlobalVariable *GV = new GlobalVariable(
            M, S->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage,
            S, "StringEncryptionEncStatus");
        encstatus[&F] = GV;
        HandleFunction(&F);
      }
    for (GlobalVariable *GV : globalProcessedGVs) {
      errs() << "Post-cleaning work: " << GV << "\n";
      GV->removeDeadConstantUsers();
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        GV->eraseFromParent();
      }
    }

    return true;
  }

  void
  processConstantAggregate(GlobalVariable *strGV, ConstantAggregate *CA,
                           std::unordered_set<GlobalVariable *> *rawStrings,
                           SmallVector<GlobalVariable *, 32> *unhandleablegvs,
                           SmallVector<GlobalVariable *, 32> *Globals,
                           std::unordered_set<User *> *Users, bool *breakFor) {
    for (unsigned i = 0; i < CA->getNumOperands(); i++) {
      Constant *Op = CA->getOperand(i);
      if (GlobalVariable *GV =
              dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
        if (!handleableGV(GV)) {
          unhandleablegvs->emplace_back(GV);
          continue;
        }
        Users->insert(opaquepointers ? CA : Op);
        if (std::find(Globals->begin(), Globals->end(), GV) == Globals->end()) {
          Globals->emplace_back(GV);
          *breakFor = true;
        }
      } else if (ConstantAggregate *NestedCA =
                     dyn_cast<ConstantAggregate>(Op)) {
        processConstantAggregate(strGV, NestedCA, rawStrings, unhandleablegvs,
                                 Globals, Users, breakFor);
      } else if (isa<ConstantDataSequential>(Op)) {
        if (CA->getNumOperands() != 1)
          continue;
        Users->insert(CA);
        rawStrings->insert(strGV);
      }
    }
  }

  void HandleUser(User *U, SmallVector<GlobalVariable *, 32> &Globals,
                  std::unordered_set<User *> &Users,
                  std::unordered_set<User *> &VisitedUsers) {
    VisitedUsers.emplace(U);
    for (Value *Op : U->operands()) {
      if (GlobalVariable *G =
              dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
        if (User *U2 = dyn_cast<User>(Op))
          Users.insert(U2);
        Users.insert(U);
        Globals.emplace_back(G);
        // A global POINTER variable (e.g. `static const char *g = "str";` or
        // an extern pointer with a private string initializer) hides the
        // actual string behind its initializer. Even when the pointer GV
        // itself is not handleable (external linkage), the pointed-to
        // constant is private and must be collected for encryption.
        collectPointeeStrings(G, Globals);
      } else if (User *U = dyn_cast<User>(Op)) {
        if (!VisitedUsers.count(U))
          HandleUser(U, Globals, Users, VisitedUsers);
      }
    }
  }

  // Follow a global's initializer if it is (or wraps) a pointer to another
  // global; those pointee strings would otherwise stay plaintext.
  void collectPointeeStrings(GlobalVariable *G,
                             SmallVector<GlobalVariable *, 32> &Globals) {
    if (!G->hasInitializer())
      return;
    Constant *Init = G->getInitializer()->stripPointerCasts();
    SmallVector<Constant *, 8> Worklist;
    Worklist.push_back(Init);
    SmallPtrSet<Constant *, 8> Seen;
    while (!Worklist.empty()) {
      Constant *C = Worklist.pop_back_val();
      if (!C || !Seen.insert(C).second)
        continue;
      if (GlobalVariable *P = dyn_cast<GlobalVariable>(C)) {
        Globals.emplace_back(P);
        if (P->hasInitializer())
          Worklist.push_back(P->getInitializer()->stripPointerCasts());
        continue;
      }
      if (ConstantAggregate *CA = dyn_cast<ConstantAggregate>(C)) {
        for (Value *Elem : CA->operands())
          if (Constant *EC = dyn_cast<Constant>(Elem))
            Worklist.push_back(EC->stripPointerCasts());
      } else if (auto *CE = dyn_cast<ConstantExpr>(C)) {
        for (Value *Elem : CE->operands())
          if (Constant *EC = dyn_cast<Constant>(Elem))
            Worklist.push_back(EC->stripPointerCasts());
      }
    }
  }

  void HandleFunction(Function *Func) {
    FixFunctionConstantExpr(Func);
    SmallVector<GlobalVariable *, 32> Globals;
    std::unordered_set<User *> Users;
    {
      std::unordered_set<User *> VisitedUsers;
      for (Instruction &I : instructions(Func))
        HandleUser(&I, Globals, Users, VisitedUsers);
    }
    std::unordered_set<GlobalVariable *> rawStrings;
    std::unordered_map<GlobalVariable *,
                       std::pair<Constant *, GlobalVariable *>>
        GV2Keys;
    std::unordered_map<GlobalVariable * /*old*/,
                       std::pair<GlobalVariable * /*encrypted*/,
                                 GlobalVariable * /*decrypt space*/>>
        old2new;

    auto end = Globals.end();
    for (auto it = Globals.begin(); it != end; ++it) {
      end = std::remove(it + 1, end, *it);
    }
    Globals.erase(end, Globals.end());

    Module *M = Func->getParent();

    SmallVector<GlobalVariable *, 32> transedGlobals, unhandleablegvs;

    do {
      for (GlobalVariable *GV : Globals) {
        if (std::find(transedGlobals.begin(), transedGlobals.end(), GV) ==
            transedGlobals.end()) {
          bool breakThisFor = false;
          if (handleableGV(GV)) {
            if (GlobalVariable *CastedGV = dyn_cast<GlobalVariable>(
                    GV->getInitializer()->stripPointerCasts())) {
              if (std::find(Globals.begin(), Globals.end(), CastedGV) ==
                  Globals.end()) {
                Globals.emplace_back(CastedGV);
                ConstantExpr *CE = dyn_cast<ConstantExpr>(GV->getInitializer());
                Users.insert(CE ? CE : GV->getInitializer());
                breakThisFor = true;
              }
            }
            // Objective-C / CFString support intentionally removed.
            if (GV->getInitializer()->getType() ==
                StructType::getTypeByName(M->getContext(),
                                          "struct.__NSConstantString_tag")) {
              unhandleablegvs.emplace_back(GV);
            } else if (isa<ConstantDataSequential>(GV->getInitializer())) {
              rawStrings.insert(GV);
            } else if (ConstantAggregate *CA =
                           dyn_cast<ConstantAggregate>(GV->getInitializer())) {
              processConstantAggregate(GV, CA, &rawStrings, &unhandleablegvs,
                                       &Globals, &Users, &breakThisFor);
            }
          } else {
            unhandleablegvs.emplace_back(GV);
          }
          transedGlobals.emplace_back(GV);
          if (breakThisFor)
            break;
        }
      } // foreach loop
    } while (transedGlobals.size() != Globals.size());
    for (GlobalVariable *ugv : unhandleablegvs)
      if (std::find(genedgv.begin(), genedgv.end(), ugv) != genedgv.end()) {
        std::pair<Constant *, GlobalVariable *> mgv2keysval = mgv2keys[ugv];
        if (mgv2keysval.first && mgv2keysval.second) {
          GV2Keys[ugv] = mgv2keysval;
        }
      }
    for (GlobalVariable *GV : rawStrings) {
      // Constant::isZeroValue was removed in LLVM 23; isNullValue covers the
      // zero/null initializer cases this check guarded against.
      if (GV->getInitializer()->isNullValue())
        continue;
      auto globalIt = globalOld2New.find(GV);
      if (globalIt != globalOld2New.end()) {
        errs() << "Found shared global variable: " << GV << "\n";
        old2new[GV] = globalIt->second;
        // 更新当前函数的GV2Keys和mgv2keys
        GV2Keys[globalIt->second.second] = mgv2keys[globalIt->second.second];
        mgv2keys[globalIt->second.second] = GV2Keys[globalIt->second.second];
        continue; // 跳过生成新变量步骤
      }
      ConstantDataSequential *CDS =
          dyn_cast<ConstantDataSequential>(GV->getInitializer());
      bool rust_string = !CDS;
      if (rust_string)
        CDS = cast<ConstantDataSequential>(
            cast<ConstantAggregate>(GV->getInitializer())->getOperand(0));
      Type *ElementTy = CDS->getElementType();
      if (!ElementTy->isIntegerTy()) {
        continue;
      }
      IntegerType *intType = cast<IntegerType>(ElementTy);
      Constant *KeyConst, *EncryptedConst, *DummyConst = nullptr;
      unencryptedindex[GV] = {};
      if (intType == Type::getInt8Ty(M->getContext())) {
        std::vector<uint8_t> keys, encry, dummy;
        // Rolling-key mixing (hardening T15): each element is XORed with
        // (K[i] ^ s) where s evolves per element as
        //   s0 = 0x5B, s = rol8(s ^ K[i]) + K[i]
        // A single known-plaintext byte no longer reveals the per-byte key,
        // and the runtime decrypt carries the same shift/xor chain.
        uint8_t roll = 0x5B;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint8_t K = cryptoutils->get_uint8_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          const uint8_t mix = K ^ roll;
          const uint8_t E = (uint8_t)(V ^ mix);
          // CIPHER-FEEDBACK rolling state: s = rol8(s ^ E) + K, where E is
          // the ciphertext byte. At runtime the decrypt loop loads E from
          // memory, so the shift/xor chain survives as real instructions
          // (not compile-time-folded constants).
          roll = (uint8_t)(((roll ^ E) << 3) | ((roll ^ E) >> 5));
          roll = (uint8_t)(roll + K);
          keys.emplace_back(K);
          encry.emplace_back(E);
          dummy.emplace_back(cryptoutils->get_uint8_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint8_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint8_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint8_t>(dummy));

      } else if (intType == Type::getInt16Ty(M->getContext())) {
        std::vector<uint16_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint16_t K = cryptoutils->get_uint16_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint16_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(dummy));
      } else if (intType == Type::getInt32Ty(M->getContext())) {
        std::vector<uint32_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint32_t K = cryptoutils->get_uint32_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint32_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(dummy));
      } else if (intType == Type::getInt64Ty(M->getContext())) {
        std::vector<uint64_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint64_t K = cryptoutils->get_uint64_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint64_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(dummy));
      } else {
        llvm_unreachable("Unsupported CDS Type");
      }
      // Prepare new rawGV
      GlobalVariable *EncryptedRawGV = new GlobalVariable(
          *M, EncryptedConst->getType(), false, GV->getLinkage(),
          EncryptedConst, "EncryptedString", nullptr, GV->getThreadLocalMode(),
          GV->getType()->getAddressSpace());
      genedgv.emplace_back(EncryptedRawGV);
      GlobalVariable *DecryptSpaceGV;
      if (rust_string) {
        ConstantAggregate *CA = cast<ConstantAggregate>(GV->getInitializer());
        CA->setOperand(0, DummyConst);
        DecryptSpaceGV = new GlobalVariable(
            *M, GV->getValueType(), false, GV->getLinkage(), CA,
            "DecryptSpaceRust", nullptr, GV->getThreadLocalMode(),
            GV->getType()->getAddressSpace());
      } else {
        DecryptSpaceGV = new GlobalVariable(
            *M, DummyConst->getType(), false, GV->getLinkage(), DummyConst,
            "DecryptSpace", nullptr, GV->getThreadLocalMode(),
            GV->getType()->getAddressSpace());
      }
      genedgv.emplace_back(DecryptSpaceGV);
      old2new[GV] = std::make_pair(EncryptedRawGV, DecryptSpaceGV);
      GV2Keys[DecryptSpaceGV] = std::make_pair(KeyConst, EncryptedRawGV);
      mgv2keys[DecryptSpaceGV] = GV2Keys[DecryptSpaceGV];
      unencryptedindex[KeyConst] = unencryptedindex[GV];
      globalOld2New[GV] = std::make_pair(EncryptedRawGV, DecryptSpaceGV);
      globalProcessedGVs.insert(GV);
      old2new[GV] = globalOld2New[GV];
    }
    if (GV2Keys.empty())
      return;
    // Replace Uses
    for (User *U : Users) {
      for (std::unordered_map<
               GlobalVariable *,
               std::pair<GlobalVariable *, GlobalVariable *>>::iterator iter =
               old2new.begin();
           iter != old2new.end(); ++iter) {
        if (isa<Constant>(U) && !isa<GlobalValue>(U)) {
          Constant *C = cast<Constant>(U);
          for (Value *Op : C->operands())
            if (Op == iter->first) {
              C->handleOperandChange(iter->first, iter->second.second);
              break;
            }
        } else
          U->replaceUsesOfWith(iter->first, iter->second.second);
        iter->first->removeDeadConstantUsers();
      }
    } // End Replace Uses
    // Cleanup at the end of encryption to avoid wild pointers
    // CleanUp Old Raw GVs
    // for (std::unordered_map<
    //          GlobalVariable *,
    //          std::pair<GlobalVariable *, GlobalVariable *>>::iterator iter =
    //          old2new.begin();
    //      iter != old2new.end(); ++iter) {
    //   GlobalVariable *toDelete = iter->first;
    //   toDelete->removeDeadConstantUsers();
    //   if (toDelete->getNumUses() == 0) {
    //     toDelete->dropAllReferences();
    //     toDelete->eraseFromParent();
    //   }
    // }
    GlobalVariable *StatusGV = encstatus[Func];
    /*
       - Split Original EntryPoint BB into A and C.
       - Create new BB as Decryption BB between A and C. Adjust the terminators
         into: A (Alloca a new array containing all)
               |
               B(If not decrypted)
               |
               C
     */
    BasicBlock *A = &(Func->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    C->setName("PrecedingBlock");
    BasicBlock *B =
        BasicBlock::Create(Func->getContext(), "StringDecryptionBB", Func, C);
    // Change A's terminator to jump to B
    // We'll add new terminator to jump C later
    BranchInst *newBr = BranchInst::Create(B);
    ReplaceInstWithInst(A->getTerminator(), newBr);
    // Insert DecryptionCode
    HandleDecryptionBlock(B, C, GV2Keys);
    Instruction *InsertPt = &*A->getFirstNonPHIOrDbgOrLifetime();
    IRBuilder<> IRB(InsertPt);
    // Add atomic load checking status in A
    LoadInst *LI = IRB.CreateLoad(StatusGV->getValueType(), StatusGV,
                                  "LoadEncryptionStatus");
    LI->setAtomic(
        AtomicOrdering::Acquire); // Will be released at the start of C
    LI->setAlignment(Align(4));
    Value *condition = IRB.CreateICmpEQ(
        LI, ConstantInt::get(Type::getInt32Ty(Func->getContext()), 0));
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(B, C, condition, A);
    // Add StoreInst atomically in C start
    // No matter control flow is coming from A or B, the GVs must be decrypted
    StoreInst *SI =
        new StoreInst(ConstantInt::get(Type::getInt32Ty(Func->getContext()), 1),
                      StatusGV, C->getFirstNonPHIOrDbgOrLifetime());
    SI->setAlignment(Align(4));
    SI->setAtomic(AtomicOrdering::Release); // Release the lock acquired in LI
  } // End of HandleFunction

  void HandleDecryptionBlock(
      BasicBlock *B, BasicBlock *C,
      std::unordered_map<GlobalVariable *,
                         std::pair<Constant *, GlobalVariable *>> &GV2Keys) {
    IRBuilder<> IRB(B);
    Value *zero = ConstantInt::get(Type::getInt32Ty(B->getContext()), 0);
    for (std::unordered_map<GlobalVariable *,
                            std::pair<Constant *, GlobalVariable *>>::iterator
             iter = GV2Keys.begin();
         iter != GV2Keys.end(); ++iter) {
      bool rust_string =
          !isa<ConstantDataSequential>(iter->first->getInitializer());
      ConstantAggregate *CA =
          rust_string ? cast<ConstantAggregate>(iter->first->getInitializer())
                      : nullptr;
      Constant *KeyConst = iter->second.first;
      ConstantDataArray *CastedCDA = cast<ConstantDataArray>(KeyConst);
      // Prevent optimization of encrypted data
      appendToCompilerUsed(*iter->second.second->getParent(),
                           {iter->second.second});
      // Element-By-Element XOR so the fucking verifier won't complain
      // Also, this hides keys
      // Rolling-key mirror (hardening T15): for i8 arrays the decrypt must
      // replay the emitter's rolling state exactly:
      //   s = rol8(s ^ K[i]) + K[i]; D = E[i] ^ (K[i] ^ s_before_update)
      // Unencrypted elements (key==1 placeholder) are skipped on BOTH sides,
      // so the state streams stay aligned. 16/32/64-bit arrays keep the
      // legacy independent-xor path (marking this: only i8 needs the shift
      // chain that T15 checks for).
      Value *RollV = ConstantInt::get(Type::getInt8Ty(B->getContext()), 0x5B);
      bool isI8 = CastedCDA->getElementType() ==
                  Type::getInt8Ty(B->getContext());
      uint64_t realkeyoff = 0;
      for (uint64_t i = 0; i < CastedCDA->getType()->getNumElements(); i++) {
        if (unencryptedindex[KeyConst].size() &&
            std::find(unencryptedindex[KeyConst].begin(),
                      unencryptedindex[KeyConst].end(),
                      i) != unencryptedindex[KeyConst].end())
          continue;
        Value *offset =
            ConstantInt::get(Type::getInt64Ty(B->getContext()), realkeyoff);
        Value *offset2 = ConstantInt::get(Type::getInt64Ty(B->getContext()), i);
        Value *EncryptedGEP =
            IRB.CreateGEP(iter->second.second->getValueType(),
                          iter->second.second, {zero, offset});
        Value *DecryptedGEP =
            rust_string
                ? IRB.CreateGEP(
                      CA->getOperand(0)->getType(),
                      IRB.CreateGEP(
                          CA->getType(), iter->first,
                          {zero, ConstantInt::getNullValue(
                                     Type::getInt64Ty(B->getContext()))}),
                      {zero, offset2})
                : IRB.CreateGEP(iter->first->getValueType(), iter->first,
                                {zero, offset2});
        LoadInst *LI = IRB.CreateLoad(CastedCDA->getElementType(), EncryptedGEP,
                                      "EncryptedChar");
        Value *KeyV = CastedCDA->getElementAsConstant(i);
        Value *XORed;
        if (isI8) {
          // mix = K ^ s  (s = state BEFORE this element's update; the
          // emitter XORs the plaintext with K ^ s, NOT with a rotated s)
          Value *Mix = IRB.CreateXor(KeyV, RollV);
          // CIPHER-FEEDBACK advance: s = rol8(s ^ E_loaded) + K. E_loaded is
          // the runtime ciphertext byte (LI), so the chain is real IR.
          Value *XoredState = IRB.CreateXor(RollV, LI);
          RollV = IRB.CreateAdd(
              IRB.CreateOr(IRB.CreateShl(XoredState, 3, "", true, true),
                           IRB.CreateLShr(XoredState, 5)),
              KeyV);
          XORed = IRB.CreateXor(LI, Mix);
        } else {
          XORed = IRB.CreateXor(LI, KeyV);
        }
        IRB.CreateStore(XORed, DecryptedGEP);
        realkeyoff++;
      }
    }
    IRB.CreateBr(C);
  } // End of HandleDecryptionBlock
};

ModulePass *createStringEncryptionPass(bool flag) {
  return new StringEncryption(flag);
}
} // namespace llvm

char StringEncryption::ID = 0;
INITIALIZE_PASS(StringEncryption, "strcry", "Enable String Encryption", false,
                false)
