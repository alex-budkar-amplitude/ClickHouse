#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

namespace
{

constexpr llvm::StringLiteral benign_annotation = "silk-tls-benign";
constexpr llvm::StringLiteral entrypoint_annotation = "silk-fiber-entrypoint";
constexpr llvm::StringLiteral prime_hook_name = "silk_tls_check_prime";
constexpr llvm::StringLiteral entrypoint_module = "src/Common/SilkFiberScheduler.cpp";

/// Swapped at every fiber switch, so it is fiber-safe by construction; never flag it.
/// (FiberLocalStorage::thread_storage — the per-thread arena underlying every FiberLocal.)
constexpr llvm::StringLiteral swapped_globals[] =
{
    "\01FiberLocalStorageThreadStorage",
};

/// Read-fresh per-thread state: correct on whichever thread runs the access, so sightings
/// at different addresses are expected. Accesses inline from headers into referencing TUs,
/// where SILK_TLS_BENIGN cannot reach (annotations emit only in the defining TU), so these
/// are allowlisted by mangled name.
/// TODO(stetsyuk): _ZN28MemoryTrackerBlockerInThread5levelE is probably not benign, and this should be done via annotation
/// not via an array.
constexpr llvm::StringLiteral benign_globals[] =
{
    "_ZN28MemoryTrackerBlockerInThread5levelE",
};

constexpr llvm::StringLiteral excluded_modules[] =
{
    "contrib/silk/",
    "contrib/jemalloc",
    "contrib/llvm-project/libcxxabi",
    "src/Common/FiberLocal.cpp",
    "src/Common/SilkTLSCheck.cpp",
    "src/Common/SilkFiberScheduler.cpp",
};

bool isExcludedModule(const llvm::Module & module)
{
    llvm::StringRef path = module.getSourceFileName();
    for (llvm::StringRef excluded : excluded_modules)
        if (path.contains(excluded))
            return true;
    return false;
}

llvm::DenseSet<const llvm::Value *> collectBenign(const llvm::Module & module)
{
    llvm::DenseSet<const llvm::Value *> benign;
    const auto * annotations = module.getGlobalVariable("llvm.global.annotations");
    if (!annotations || !annotations->hasInitializer())
        return benign;

    const auto * entries = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
    if (!entries)
        return benign;

    for (const llvm::Use & entry : entries->operands())
    {
        const auto * record = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
        if (!record || record->getNumOperands() < 2)
            continue;
        const auto * text_holder = llvm::dyn_cast<llvm::GlobalVariable>(record->getOperand(1)->stripPointerCasts());
        if (!text_holder || !text_holder->hasInitializer())
            continue;
        const auto * text = llvm::dyn_cast<llvm::ConstantDataArray>(text_holder->getInitializer());
        if (!text || !text->isCString())
            continue;
        if (text->getAsCString() == benign_annotation)
            benign.insert(record->getOperand(0)->stripPointerCasts());
    }
    return benign;
}

llvm::SmallVector<llvm::Function *> collectEntrypoints(const llvm::Module & module)
{
    llvm::SmallVector<llvm::Function *> entrypoints;
    const auto * annotations = module.getGlobalVariable("llvm.global.annotations");
    if (!annotations || !annotations->hasInitializer())
        return entrypoints;

    const auto * entries = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
    if (!entries)
        return entrypoints;

    for (const llvm::Use & entry : entries->operands())
    {
        const auto * record = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
        if (!record || record->getNumOperands() < 2)
            continue;
        const auto * text_holder = llvm::dyn_cast<llvm::GlobalVariable>(record->getOperand(1)->stripPointerCasts());
        if (!text_holder || !text_holder->hasInitializer())
            continue;
        const auto * text = llvm::dyn_cast<llvm::ConstantDataArray>(text_holder->getInitializer());
        if (!text || !text->isCString())
            continue;
        if (text->getAsCString() != entrypoint_annotation)
            continue;
        if (auto * function = llvm::dyn_cast<llvm::Function>(record->getOperand(0)->stripPointerCasts()))
            if (!function->isDeclaration())
                entrypoints.push_back(function);
    }
    return entrypoints;
}

/// Prepend a silk_tls_check_prime() call to every SILK_FIBER_ENTRYPOINT function, so the
/// detector's per-fiber state is created at fiber start rather than at an arbitrary TLS access.
/// The build carries exactly one entrypoint, in the fiber scheduler module; anything else
/// means the priming silently stopped working, so fail the build instead.
bool injectEntrypointPrimes(llvm::Module & module)
{
    llvm::SmallVector<llvm::Function *> entrypoints = collectEntrypoints(module);

    if (module.getSourceFileName().find(entrypoint_module.str()) != std::string::npos)
    {
        if (entrypoints.size() != 1)
            llvm::report_fatal_error("silk-tls-check: expected exactly one SILK_FIBER_ENTRYPOINT in " + entrypoint_module);
    }
    else if (!entrypoints.empty())
    {
        llvm::report_fatal_error("silk-tls-check: unexpected SILK_FIBER_ENTRYPOINT in " + llvm::Twine(module.getSourceFileName()));
    }

    if (entrypoints.empty())
        return false;

    llvm::LLVMContext & context = module.getContext();
    llvm::FunctionCallee prime = module.getOrInsertFunction(
        prime_hook_name, llvm::FunctionType::get(llvm::Type::getVoidTy(context), false));

    for (llvm::Function * function : entrypoints)
    {
        llvm::IRBuilder<> builder(&function->getEntryBlock(), function->getEntryBlock().getFirstInsertionPt());
        builder.CreateCall(prime);
    }
    return true;
}

struct SilkTLSCheck : llvm::PassInfoMixin<SilkTLSCheck>
{
    llvm::PreservedAnalyses run(llvm::Module & module, llvm::ModuleAnalysisManager &)
    {
        const bool primed = injectEntrypointPrimes(module);

        if (isExcludedModule(module))
            return primed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();

        llvm::SmallVector<llvm::CallInst *> accesses;
        for (llvm::Function & function : module)
            if (function.getIntrinsicID() == llvm::Intrinsic::threadlocal_address)
                for (llvm::User * user : function.users())
                    if (auto * call = llvm::dyn_cast<llvm::CallInst>(user))
                        accesses.push_back(call);

        if (accesses.empty())
            return primed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();

        llvm::DenseSet<const llvm::Value *> benign = collectBenign(module);

        llvm::LLVMContext & context = module.getContext();
        llvm::PointerType * ptr = llvm::PointerType::getUnqual(context);
        auto * hook = llvm::cast<llvm::Function>(module.getOrInsertFunction(
            "check_silk_tls_access",
            llvm::FunctionType::get(llvm::Type::getVoidTy(context), {ptr, ptr}, false)).getCallee());

        if (hook->isDeclaration())
        {
            hook->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
            hook->addFnAttr(llvm::Attribute::NoInline);
            llvm::IRBuilder<>(llvm::BasicBlock::Create(context, "", hook)).CreateRetVoid();
        }

        llvm::DenseMap<const llvm::Value *, llvm::Constant *> variable_names;
        bool changed = false;
        for (llvm::CallInst * access : accesses)
        {
            const llvm::Value * variable = access->getArgOperand(0)->stripPointerCastsAndAliases();
            if (benign.contains(variable))
                continue;
            if (llvm::any_of(swapped_globals, [&](llvm::StringRef s) { return variable->getName() == s; }))
                continue;
            if (llvm::any_of(benign_globals, [&](llvm::StringRef s) { return variable->getName() == s; }))
                continue;
            llvm::IRBuilder<> builder(access->getParent(), std::next(access->getIterator()));
            llvm::Constant *& name = variable_names[variable];
            if (!name)
                name = builder.CreateGlobalString(variable->getName());
            builder.CreateCall(hook, {access, name});
            changed = true;
        }

        return (changed || primed) ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }
};

}

extern "C" LLVM_ATTRIBUTE_WEAK llvm::PassPluginLibraryInfo llvmGetPassPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "SilkTLSCheck", LLVM_VERSION_STRING,
        [](llvm::PassBuilder & pass_builder)
        {
            pass_builder.registerPipelineStartEPCallback(
                [](llvm::ModulePassManager & manager, llvm::OptimizationLevel) { manager.addPass(SilkTLSCheck()); });
        }};
}
