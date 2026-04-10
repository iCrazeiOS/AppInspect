/**
 * Hook detection for jailbreak tweaks.
 *
 * Scans symbols, classes, and strings for evidence of hooking frameworks
 * (Substrate, Libhooker, fishhook, Substitute) and ObjC runtime swizzling.
 */

import type {
  Symbol as SymbolEntry,
  ObjCClass,
  StringEntry,
  HookInfo,
} from "../../shared/types";

/** Known hook framework symbols → framework name */
export const HOOK_SYMBOLS: Record<string, string> = {
  "_MSHookMessageEx": "Substrate",
  "_MSHookFunction": "Substrate",
  "_MSHookClassPair": "Substrate",
  "_MSGetImageByName": "Substrate",
  "_MSFindSymbol": "Substrate",
  "_LHHookMessageEx": "Libhooker",
  "_LHHookFunction": "Libhooker",
  "_LHOpenImage": "Libhooker",
  "_LBHookMessage": "Libhooker",
  "_rebind_symbols": "fishhook",
  "_rebind_symbols_image": "fishhook",
  "_substitute_hook_functions": "Substitute",
  "_SubHookMessageEx": "Substitute",
  // ObjC runtime swizzling APIs (used by compiled Logos/Theos tweaks)
  "_class_replaceMethod": "ObjC Runtime",
  "_method_setImplementation": "ObjC Runtime",
  "_method_exchangeImplementations": "ObjC Runtime",
};

/** System class prefixes (unlikely to be defined by a tweak) */
export const SYSTEM_CLASS_PREFIXES = [
  "UI", "NS", "CA", "CK", "AV", "MF", "WK", "SK", "SB", "SF",
  "MP", "PH", "CL", "MK", "SC", "GK", "HK", "CN", "EK", "AS",
  "CT", "NW", "ST", "TI", "AB", "MB", "LS", "BS", "FBS", "RBS",
  "CSP", "SSB", "SFL", "SPT", "NCN", "BLT", "WiFi", "CarPlay",
  "Spring", "Web", "WAK", "DOM",
];

export function detectHooks(
  symbols: SymbolEntry[],
  classes: ObjCClass[],
  strings: StringEntry[],
): HookInfo {
  const frameworks = new Set<string>();
  const hookSymbols: string[] = [];
  const hookedClasses = new Set<string>();

  // 1. Check imported symbols for hook framework functions
  for (const sym of symbols) {
    if (sym.type !== "imported") continue;
    const framework = HOOK_SYMBOLS[sym.name];
    if (framework) {
      frameworks.add(framework);
      hookSymbols.push(sym.name);
    }
  }

  // 2. Find system classes referenced by the binary.
  //    Only when a hook framework is present — regular apps also reference
  //    system classes via objc_getClass for normal usage.
  if (frameworks.size > 0) {
    const tweakClassNames = new Set(classes.map((c) => c.name));

    for (const str of strings) {
      const val = str.value;
      if (val.length < 3 || val.length > 80 || !/^[A-Z]/.test(val)) continue;
      if (/[\s@#$%^&*(){}[\]|\\<>,]/.test(val)) continue;
      if (tweakClassNames.has(val)) continue;

      for (const prefix of SYSTEM_CLASS_PREFIXES) {
        if (val.startsWith(prefix) && val.length > prefix.length && /^[A-Z]/.test(val[prefix.length]!)) {
          hookedClasses.add(val);
          break;
        }
      }
    }
  }

  return {
    frameworks: [...frameworks],
    targetBundles: [],
    hookedClasses: [...hookedClasses].sort(),
    hookSymbols,
  };
}
