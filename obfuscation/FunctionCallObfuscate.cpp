// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/FunctionCallObfuscate.h"
#include "json.hpp"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>

using namespace llvm;

static const int DARWIN_FLAG = 0x2 | 0x8;
static const int ANDROID64_FLAG = 0x00002 | 0x100;
static const int ANDROID32_FLAG = 0x0000 | 0x2;

static cl::opt<uint64_t>
    dlopen_flag("fco_flag",
                cl::desc("The value of RTLD_DEFAULT on your platform"),
                cl::value_desc("value"), cl::init(-1), cl::Optional);
static cl::opt<std::string>
    SymbolConfigPath("fcoconfig",
                     cl::desc("FunctionCallObfuscate Configuration Path"),
                     cl::value_desc("filename"), cl::init("+-x/"));
namespace llvm {
struct FunctionCallObfuscate : public FunctionPass {
  static char ID;
  nlohmann::json Configuration;
  bool flag;
  bool initialized;
  bool opaquepointers;
  Triple triple;
  FunctionCallObfuscate() : FunctionPass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  FunctionCallObfuscate(bool flag) : FunctionPass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "FunctionCallObfuscate"; }
  bool initialize(Module &M) {
    // Basic Defs
    if (SymbolConfigPath == "+-x/") {
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
        sys::path::append(Path, "Hikari", "SymbolConfig.json");
        SymbolConfigPath = Path.c_str();
      }
    }
    std::ifstream infile(SymbolConfigPath);
    if (infile.good()) {
      errs() << "Loading Symbol Configuration From:" << SymbolConfigPath
             << "\n";
      infile >> this->Configuration;
    } else {
      errs() << "Failed To Load Symbol Configuration From:" << SymbolConfigPath
             << "\n";
    }
    this->triple = Triple(M.getTargetTriple());
    this->initialized = true;
#if LLVM_VERSION_MAJOR >= 17
    this->opaquepointers = true;
#else
    this->opaquepointers = !M.getContext().supportsTypedPointers();
#endif
    return true;
  }

  bool runOnFunction(Function &F) override {
    // Construct Function Prototypes
    if (!toObfuscate(flag, &F, "fco"))
      return false;
    errs() << "Running FunctionCallObfuscate On " << F.getName() << "\n";
    Module *M = F.getParent();
    if (!this->initialized)
      initialize(*M);
    if (!triple.isAndroid() && !triple.isOSDarwin()) {
      errs() << "Unsupported Target Triple: " << M->getTargetTriple().str() << "\n";
      return false;
    }
    FixFunctionConstantExpr(&F);
    Type *Int32Ty = Type::getInt32Ty(M->getContext());
    Type *Int8PtrTy = PointerType::get(M->getContext(), 0);
    FunctionType *dlopen_type = FunctionType::get(
        Int8PtrTy, {Int8PtrTy, Int32Ty},
        false); // int has a length of 32 on both 32/64bit platform
    FunctionType *dlsym_type =
        FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, false);
    Function *dlopen_decl = cast<Function>(
        M->getOrInsertFunction("dlopen", dlopen_type).getCallee());
    Function *dlsym_decl =
        cast<Function>(M->getOrInsertFunction("dlsym", dlsym_type).getCallee());
    // Begin Iteration
    for (BasicBlock &BB : F) {
      for (Instruction &Inst : BB) {
        if (isa<CallInst>(&Inst) || isa<InvokeInst>(&Inst)) {
          CallSite CS(&Inst);
          Function *calledFunction = CS.getCalledFunction();
          if (!calledFunction) {
            /*
              Note:
              For Indirect Calls:
                CalledFunction is NULL and calledValue is usually a bitcasted
              function pointer. We'll need to strip out the hiccups and obtain
              the called Function* from there
            */
            calledFunction =
                dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
          }
          // Simple Extracting Failed
          // Use our own implementation
          if (!calledFunction)
            continue;
#if LLVM_VERSION_MAJOR >= 18
          if (calledFunction->getName().starts_with("hikari_"))
#else
          if (calledFunction->getName().startswith("hikari_"))
#endif
            continue;

          // It's only safe to restrict our modification to external symbols
          // Otherwise stripped binary will crash
          if (!calledFunction->empty() ||
              calledFunction->getName().equals_insensitive("dlsym") ||
              calledFunction->getName().equals_insensitive("dlopen") ||
              calledFunction->isIntrinsic())
            continue;

          if (this->Configuration.find(calledFunction->getName().str()) !=
              this->Configuration.end()) {
            std::string sname =
                this->Configuration[calledFunction->getName().str()]
                    .get<std::string>();
            StringRef calledFunctionName = StringRef(sname);
            BasicBlock *EntryBlock = CS->getParent();
            if (triple.isOSDarwin()) {
              dlopen_flag = DARWIN_FLAG;
            } else if (triple.isAndroid()) {
              if (triple.isArch64Bit())
                dlopen_flag = ANDROID64_FLAG;
              else
                dlopen_flag = ANDROID32_FLAG;
            } else {
              errs() << "[FunctionCallObfuscate] Unsupported Target Triple:"
                     << M->getTargetTriple().str() << "\n";
              errs() << "[FunctionCallObfuscate] Applying Default Signature:"
                     << dlopen_flag << "\n";
            }
            IRBuilder<> IRB(EntryBlock, EntryBlock->getFirstInsertionPt());
            Value *Handle = IRB.CreateCall(
                dlopen_decl, {Constant::getNullValue(Int8PtrTy),
                              ConstantInt::get(Int32Ty, dlopen_flag)});
            // Create dlsym call
            Value *fp = IRB.CreateCall(
                dlsym_decl,
                {Handle, IRB.CreateGlobalString(calledFunctionName)});
            Value *bitCastedFunction =
                IRB.CreateBitCast(fp, CS.getCalledValue()->getType());
            CS.setCalledFunction(bitCastedFunction);
          }
        }
      }
    }
    return true;
  }
};
FunctionPass *createFunctionCallObfuscatePass(bool flag) {
  return new FunctionCallObfuscate(flag);
}
} // namespace llvm
char FunctionCallObfuscate::ID = 0;
INITIALIZE_PASS(FunctionCallObfuscate, "fcoobf",
                "Enable Function CallSite Obfuscation.", false, false)
