#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <remill/BC/Util.h>
#include <algorithm>

namespace anvill {


class PointerLifter : public llvm::InstVisitor<PointerLifter, llvm::Value*> {
    public:
        PointerLifter(llvm::Module& mod): module(mod) {}

        // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst 
        // Adds users to the next worklist, for downstream type propagation 
        void ReplaceAllUses(llvm::Value* orig_inst, llvm::Value* new_inst);

        // We need to get a pointer from some value  
        [[nodiscard]] llvm::Value * getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value * curr_val, llvm::Type* dest_type);
        
        // These visitor methods indicate that we know about pointer information to propagate
        // Some are maybes, because not all cast instructions are casts to pointers. 
        [[nodiscard]] llvm::Value* visitIntToPtrInst(llvm::IntToPtrInst *inst);
        [[nodiscard]] llvm::Value* visitPtrToIntInst(llvm::PtrToIntInst *inst);
        [[nodiscard]] llvm::Value* visitGetElementPtrInst(llvm::GetElementPtrInst *inst);
        [[nodiscard]] llvm::Value* visitBitCastInst(llvm::BitCastInst *inst);
        [[nodiscard]] llvm::Value* visitCastInst(llvm::CastInst *inst);
        // Simple wrapper for storing the type information into the list, and then calling visit.
        [[nodiscard]] llvm::Value* visitInferInst(llvm::Instruction* inst, llvm::Type* inferred_type);
        [[nodiscard]] llvm::Value* GetIndexedPointer(llvm::Value* address, llvm::Value* offset);

        // Other funcs
        [[nodiscard]] llvm::Value* visitBinaryOperator(llvm::BinaryOperator* inst);

        // Driver method 
        void LiftFunction(llvm::Function* func);

        /*
        // TODO (Carson)
        if you see an intoptr on a load, then you'll want to rewrite the load to be a load on a bitcast
        i.e. to load a pointer from mrmory, rather than an int
        */
        
    private:
        std::unordered_map<llvm::Instruction*, llvm::Type*> inferred_types;
        std::vector<llvm::Instruction*> next_worklist;
        llvm::Module& module;

};

// Creates a cast of val to a dest type. 
// This casts whatever value we want to a pointer, propagating the information
[[nodiscard]] llvm::Value* PointerLifter::getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value * val, llvm::Type* dest_type) {
    // is the value another instruction? Visit it 
    return ir.CreateBitOrPointerCast(val, dest_type);
}

llvm::Value* PointerLifter::visitInferInst(llvm::Instruction * inst, llvm::Type* inferred_type) {
    inferred_types[inst] = inferred_type;
    return visit(inst);
}

llvm::Value* PointerLifter::GetIndexedPointer(llvm::Value* address, llvm::Value* offset) {

}

/*
    Replace next_worklist iteration with just a bool `changed`, set changed=true here.
    iterate over the original worklist until changed is false. 

    is there a bad recursion case here?

    Create map from Value --> Value, maintains seen/cached changes. 
*/

void PointerLifter::ReplaceAllUses(llvm::Value *old_val, llvm::Value *new_val) {
  DCHECK(!llvm::isa<llvm::Constant>(old_val));
  for (auto user : old_val->users()) {
    if (auto inst = llvm::dyn_cast<llvm::Instruction>(user)) {
      next_worklist.push_back(inst);
    }
  }
  old_val->replaceAllUsesWith(new_val);
}


/*
inttoptr instructions indicate there are pointers. There are two cases:
1. %X = inttoptr i32 255 to i32*

%y = i32 4193555
%A = add %y, 4
2. %X = inttoptr i32 %A to i32*

In the first case, only %X is a pointer, this should already be known by the compiler 
In the second case, it indicates that %Y although of type integer, has been a pointer
*/
llvm::Value* PointerLifter::visitIntToPtrInst(llvm::IntToPtrInst* inst) {
    llvm::Value* pointer_operand = inst->getOperand(0);
    if (auto pointer_inst = llvm::dyn_cast<llvm::Instruction>(pointer_operand)) {
        // This is the inferred type
        llvm::Type* dest_type = inst->getDestTy();
        // Propagate that type upto the original register containing the value
        // Create an entry in updated val with pointer cast.
        llvm::Value * new_ptr = visitInferInst(pointer_inst, dest_type);
        ReplaceAllUses(inst, new_ptr);
        return new_ptr;
    }
    return inst;
}

/*
Binary operators such as add, sub, mul, etc

Ultimately we want to eliminate the operation and replace it with a GEP when we can,
or just cast the result if is needed.

Here is an example with an add. 

Original: 
%A = i32 419444 <------- Here we see that %A is an i32, create a new pointer for this. 
%B = i32 add %A 8 <---------- Here we see that %B is an add, Visit the instruction %A
%C = inttoptr %B <---- Here we infer that %B is really a pointer. Visit %B
-----------------------^ Start 

Intermediate 
%A = i32 419444
%A_PTR = i32* 41944 <------- Create a new ptr type, Mark updated vals as A ---> A_PTR  
%B = i32 add %A 8 
%C = inttoptr %B 

Intermediate 2 
%A = i32 419444
%A_PTR = i32* 41944 
%B = i32 add %A 8 
%B_GEP = i32* GEP %A_PTR, <indexes> <--- Visit returns with the new A_PTR, Create a GEP, B ---> B_GEP 
%C = inttoptr %B 

Intermediate 3
%A = i32 419444
%A_PTR = i32* 41944 
%B = i32 add %A 8
%B_GEP = i32* GEP %A_PTR, <indexes>
%C = inttoptr %B  <--- Update uses of C --> B_GEP. 

Then later when uses are actually replaced 
(A-->A_PTR), (B-->B_GEP), (C-->B_GEP)

and optimizations are applied we are left with

%A_PTR = i32* 41944 
%B_GEP = i32* GEP %A_PTR <indexes>

*/
llvm::Value* PointerLifter::visitBinaryOperator(llvm::BinaryOperator* inst) {
    // Adds by themselves do not infer pointer info
    if (inferred_types.find(inst) == inferred_types.end()) {
        return;
    }
    llvm::Type* inferred_type = inferred_types[inst];
    // If we are coming from downstream, then we have an inferred type.
    const auto lhs_op = inst->getOperand(0);
    const auto rhs_op = inst->getOperand(1);
    auto lhs_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(lhs_op);
    auto rhs_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(rhs_op);

    // In the original GetPointer code, there is a case that logs an error 
    // When both addresses are pointers, because its weird, and im not sure why that would be
    if (lhs_ptr && rhs_ptr) {
        llvm::IRBuilder ir(inst->getNextNode());
        const auto bb = ir.GetInsertBlock();

      LOG(ERROR) << "Two pointers " << remill::LLVMThingToString(lhs_ptr) << " and "
                 << remill::LLVMThingToString(rhs_ptr) << " are added together "
                 << remill::LLVMThingToString(inst) << " in block "
                 << bb->getName().str() << " in function "
                 << bb->getParent()->getName().str();

      llvm::Value * new_pointer = ir.CreateIntToPtr(inst, inferred_type);
      ReplaceAllUses(inst, new_pointer);
      return new_pointer;
    }

    // If neither of them are known pointers, then we have some inference to propagate!
    else if (!lhs_ptr && !rhs_ptr) {
        auto lhs_inst = llvm::dyn_cast<llvm::Instruction>(lhs_op);
        auto rhs_inst = llvm::dyn_cast<llvm::Instruction>(rhs_op);
        if (lhs_inst) {
            // visit it! propagate type information. 
            inferred_types[lhs_inst] = inferred_type;
            llvm::Value* ptr_val = visit(lhs_inst);
            // ^ should be in updated vals. Next create an indexed pointer
            // This could be a GEP, but in some cases might just be a bitcast.
            auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);
            CHECK_NE(rhs_const, nullptr);
            CHECK_EQ(rhs_inst, nullptr);
            // Create the GEP/Indexed pointer
            llvm::Value* indexed_pointer = GetIndexedPointer(lhs_inst, rhs_const);
            // Mark as updated 
            ReplaceAllUses(inst, indexed_pointer);
            return indexed_pointer;
        }
        // Same but for RHS
        else if (rhs_inst) {
            inferred_types[rhs_inst] = inferred_type;
            llvm::Value* ptr_val = visit(rhs_inst);
            auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op);
            CHECK_NE(lhs_const, nullptr);
            CHECK_EQ(lhs_inst, nullptr);
            llvm::Value* indexed_pointer = GetIndexedPointer(rhs_inst, lhs_const);
            ReplaceAllUses(inst, indexed_pointer);
            return indexed_pointer;
        }
        // We know there is some pointer info, but they are both consts? 
        else {
            // We don't have a L/RHS instruction, just create a pointer
            llvm::IRBuilder ir(inst->getNextNode());
            llvm::Value* add_ptr = ir.CreateIntToPtr(inst, inferred_type);
            ReplaceAllUses(inst, add_ptr);
            return add_ptr;
        }
    }
    // Default behavior is just to cast, this is not ideal, because 
    // we want to try and propagate as much as we can. 
    llvm::IRBuilder ir(inst->getNextNode());
    llvm::Value* default_cast = ir.CreateBitCast(inst, inferred_type);
    ReplaceAllUses(inst, default_cast);
    return default_cast;
}
/*
This is the driver code for the pointer lifter

It creates a worklist out of the instructions in the original function and visits them. 
In order to do downstream pointer propagation, additional uses of updated values are added into the next_worklist 
Pointer lifting for a function is done when we reach a fixed point, when the next_worklist is empty. 
*/
void PointerLifter::LiftFunction(llvm::Function* func) {
    std::vector<llvm::Instruction*> worklist;
    std::vector<llvm::Instruction*> next_worklist;

    for (auto& block : *func) {
        for (auto& inst : block) {
            worklist.push_back(&inst);
        }
    }
    do {
        for (auto inst: worklist) {
            visit(inst);
        }
        worklist.swap(next_worklist);
        next_worklist.clear();
        
        // Remove duplicate instructions.
        std::sort(worklist.begin(), worklist.end());
        auto it = std::unique(worklist.begin(), worklist.end());
        worklist.erase(it, worklist.end());

    } while(!next_worklist.empty());
}

}; // anvill