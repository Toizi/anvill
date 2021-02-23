#ifndef __POINTER_LIFTER
#define __POINTER_LIFTER

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <unordered_map>

namespace anvill {

class PointerLifter : public llvm::InstVisitor<PointerLifter, llvm::Value *> {
 public:
  PointerLifter(llvm::Module &mod) : module(mod) {}

  // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst
  // Adds users to the next worklist, for downstream type propagation
  void ReplaceAllUses(llvm::Value *orig_inst, llvm::Value *new_inst);

  // We need to get a pointer from some value
  llvm::Value *getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value *curr_val,
                                 llvm::Type *dest_type);

  // These visitor methods indicate that we know about pointer information to propagate
  // Some are maybes, because not all cast instructions are casts to pointers.
  llvm::Value *visitIntToPtrInst(llvm::IntToPtrInst &inst);
  llvm::Value *visitLoadInst(llvm::LoadInst &inst);
  llvm::ConstantExpr *visitConstantExpr(llvm::ConstantExpr &c);
  //llvm::Value *visitPtrToIntInst(llvm::PtrToIntInst &inst);
  //llvm::Value *visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  //llvm::Value *visitBitCastInst(llvm::BitCastInst &inst);
  //llvm::Value *visitCastInst(llvm::CastInst &inst);
  // Simple wrapper for storing the type information into the list, and then calling visit.
  llvm::Value *visitInferInst(llvm::Instruction *inst,
                              llvm::Type *inferred_type);
  llvm::Value *GetIndexedPointer(llvm::Value *address, llvm::Value *offset);
  llvm::Value *visitInstruction(llvm::Instruction &I);
  // Other funcs
  llvm::Value *visitBinaryOperator(llvm::BinaryOperator &inst);

  // Driver method
  void LiftFunction(llvm::Function *func);

  /*
        // TODO (Carson)
        if you see an intoptr on a load, then you'll want to rewrite the load to be a load on a bitcast
        i.e. to load a pointer from mrmory, rather than an int
  */

 private:
  std::unordered_map<llvm::Value *, llvm::Type *> inferred_types;
  std::vector<llvm::Instruction *> next_worklist;
  llvm::Module &module;
};

};  // namespace anvill

#endif